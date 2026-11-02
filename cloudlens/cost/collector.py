"""Scheduling: run every estimator across every account and region, on its own cadence.

The unit of work is one (estimator, account, region) triple. They are independent, so
they fan out across a thread pool - which matters, because a 10-account x 4-region x
25-estimator sweep is a thousand tasks and doing them serially would take longer than
the scrape interval.

Each cadence gets its own loop so that a slow hourly Cost Explorer pass can never
delay the 60-second Lambda pass.
"""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import boto3

from ..accounts import AccountSession, build_sessions
from .base import Context, Estimator, select
from ..config import Config
from .estimators import _util
from .exporter import CostRegistry
from .models import ResourceCost, Tier
from .pricing import PricingClient

log = logging.getLogger(__name__)


@dataclass
class Task:
    estimator: Estimator
    session: AccountSession
    region: str


class Collector:
    def __init__(self, config: Config, registry: CostRegistry):
        self.config = config
        self.registry = registry
        self.sessions = build_sessions(config.accounts)
        self.estimators = select(config.estimators, config.disabled_estimators)
        self.tag_keys = tuple(config.tag_keys)

        # The Pricing API is a public catalogue - any credentials can read it, so it
        # is queried once from the collector's own identity rather than per account.
        self.pricing = PricingClient(
            boto3.Session(), config.pricing_cache_dir, config.pricing_cache_ttl
        )
        _util.set_fallback_hook(registry.record_pricing_fallback)

        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

        by_cadence: dict[str, list[Estimator]] = {}
        for est in self.estimators:
            by_cadence.setdefault(est.cadence, []).append(est)
        self.by_cadence = by_cadence

        log.info(
            "loaded %d estimators across %d accounts: %s",
            len(self.estimators), len(self.sessions),
            ", ".join(sorted(e.name for e in self.estimators)),
        )

    # ------------------------------------------------------------------ run

    def start(self) -> None:
        intervals = {
            "realtime": self.config.scrape_interval,
            "inventory": self.config.inventory_interval,
            "billing": self.config.billing_interval,
        }
        for cadence, estimators in self.by_cadence.items():
            if cadence == "billing" and not self.config.ce_enabled:
                log.info("cost_explorer disabled by config")
                continue
            thread = threading.Thread(
                target=self._loop,
                args=(cadence, estimators, intervals.get(cadence, 300)),
                name="cloudlens-" + cadence,
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=10)

    def run_once(self) -> list[ResourceCost]:
        """Single synchronous sweep of every estimator. Used by `cloudlens once`."""
        collected: list[ResourceCost] = []
        for cadence, estimators in self.by_cadence.items():
            if cadence == "billing" and not self.config.ce_enabled:
                continue
            collected.extend(self._sweep(estimators))
        self._reconcile()
        return collected

    def _loop(self, cadence: str, estimators: list[Estimator], interval: int) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self._sweep(estimators)
                if cadence == "billing":
                    self._reconcile()
            except Exception:  # noqa: BLE001 - a loop that dies stops all monitoring
                log.exception("%s sweep failed", cadence)

            self.registry.record_pricing_stats(
                self.pricing.lookups, self.pricing.cache_hits
            )
            elapsed = time.monotonic() - started
            if elapsed > interval:
                log.warning(
                    "%s sweep took %.1fs, longer than its %ds interval - "
                    "raise the interval or lower the region/account count",
                    cadence, elapsed, interval,
                )
            self._stop.wait(max(interval - elapsed, 1.0))

    # -------------------------------------------------------------- internals

    def _sweep(self, estimators: list[Estimator]) -> list[ResourceCost]:
        # Check reachability once per account per sweep, not once per task. An account
        # that is down gets its tasks recorded as failures rather than silently
        # returning zero cost - otherwise a broken role reads as "nothing to bill".
        reachable = {id(s): s.healthy() for s in self.sessions}

        tasks = []
        for task in self._build_tasks(estimators):
            if reachable[id(task.session)]:
                tasks.append(task)
            else:
                self.registry.record_collection(
                    task.estimator.name, task.session.cfg.account_id,
                    task.region, 0.0, ok=False,
                )
        if not tasks:
            return []

        results: list[ResourceCost] = []
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as pool:
            futures = {pool.submit(self._run_task, t): t for t in tasks}
            for future in as_completed(futures):
                task = futures[future]
                try:
                    results.extend(future.result())
                except Exception as exc:  # noqa: BLE001
                    log.warning("%s/%s/%s raised: %s", task.estimator.name,
                                task.session.name, task.region, exc)
        return results

    def _build_tasks(self, estimators: list[Estimator]) -> list[Task]:
        tasks: list[Task] = []
        for session in self.sessions:
            regions = self.config.regions_for(session.cfg)
            for est in estimators:
                if est.global_service:
                    # One pass per account. us-east-1 is where the global services
                    # keep their control planes and metrics.
                    tasks.append(Task(est, session, "us-east-1"))
                else:
                    tasks.extend(Task(est, session, r) for r in regions)
        return tasks

    def _run_task(self, task: Task) -> list[ResourceCost]:
        ctx = Context(
            session=task.session,
            region=task.region,
            pricing=self.pricing,
            window=max(self.config.scrape_interval * 3, 300),
            tag_keys=self.tag_keys,
        )
        started = time.monotonic()
        ok = True
        costs: list[ResourceCost] = []
        try:
            costs = list(task.estimator.collect(ctx))
        except Exception:  # noqa: BLE001
            ok = False
            log.exception("%s failed in %s/%s", task.estimator.name,
                          task.session.name, task.region)
        duration = time.monotonic() - started

        account_id = task.session.account_id
        self.registry.record_collection(
            task.estimator.name, account_id, task.region, duration, ok
        )
        if ok:
            group = (account_id,
                     "global" if task.estimator.global_service else task.region,
                     task.estimator.name)
            self.registry.update(costs, groups=[group])
        return costs

    def _reconcile(self) -> None:
        """Publish estimate-vs-actual drift per account and service.

        Compares Cost Explorer's most recent complete day against the current derived
        run-rate extrapolated over 24 hours. That comparison is exact for steady
        workloads and noisy for spiky ones - which is itself the useful signal, since a
        ratio that sits stably below 1.0 is almost always a Savings Plan or Reserved
        Instance discount the on-demand estimators cannot see.
        """
        with self.registry._lock:  # noqa: SLF001 - same package, intentional
            rates = dict(self.registry._rates)  # noqa: SLF001

        labels = self.registry._labels  # noqa: SLF001
        i_account, i_service, i_tier = (
            labels.index("account_id"), labels.index("service"), labels.index("tier")
        )

        estimated: dict[tuple[str, str], float] = {}
        actual: dict[tuple[str, str], float] = {}
        for key, rate in rates.items():
            bucket = (key[i_account], key[i_service])
            if key[i_tier] == Tier.BILLING.value:
                actual[bucket] = actual.get(bucket, 0.0) + rate
            else:
                estimated[bucket] = estimated.get(bucket, 0.0) + rate

        for bucket, actual_rate in actual.items():
            est_rate = estimated.get(bucket)
            if est_rate is None or actual_rate <= 0:
                continue
            self.registry.record_drift(bucket[0], bucket[1], est_rate / actual_rate)
