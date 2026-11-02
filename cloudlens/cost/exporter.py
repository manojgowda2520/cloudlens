"""Prometheus exposition.

Two views of the same number, because they answer different questions:

  cloudlens_resource_usd_per_hour   gauge   - "what is this thing costing me right now"
  cloudlens_resource_usd_total      counter - "what has it cost since the collector started"

The counter is integrated from the gauge rather than read from AWS: on every snapshot
each series accrues rate x elapsed. That makes a missed or slow scrape lose a little
accuracy but never double-count, and lets `increase()` and `rate()` work normally in
PromQL over any window.

Cardinality is the real operational risk here - a big account has tens of thousands of
log groups and Lambda versions, and one series per resource per dimension will melt a
small Prometheus. Two guards: a floor on hourly rate, and a top-N cap per
(account, region, service) with everything below it folded into a single __other__
series so the totals still add up.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict

from prometheus_client import CollectorRegistry
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

from .models import ResourceCost, _sanitize

log = logging.getLogger(__name__)

OTHER = "__other__"
STALE_AFTER = 3600.0   # drop a series that has not been seen for an hour


class CostRegistry:
    """Thread-safe store of the latest cost snapshot, exposed as Prometheus metrics."""

    def __init__(self, tag_keys: tuple[str, ...] = (), top_n: int = 200,
                 min_usd_per_hour: float = 0.0):
        self.tag_keys = tag_keys
        self.top_n = top_n
        self.min_usd_per_hour = min_usd_per_hour

        self._lock = threading.Lock()
        self._rates: dict[tuple, float] = {}
        self._totals: dict[tuple, float] = defaultdict(float)
        self._seen: dict[tuple, float] = {}       # last time the total was integrated
        self._reported: dict[tuple, float] = {}   # last time a batch mentioned it

        self._labels = (
            "account_id", "account_name", "region", "service",
            "resource_type", "resource_id", "dimension", "tier",
        ) + tuple("tag_" + _sanitize(k) for k in tag_keys)

        # Operational counters.
        self._collections: dict[tuple[str, str, str], float] = defaultdict(float)
        self._errors: dict[tuple[str, str, str], float] = defaultdict(float)
        self._durations: dict[tuple[str, str, str], float] = {}
        self._last_success: dict[tuple[str, str, str], float] = {}
        self._pricing_fallbacks: dict[tuple[str, str], float] = defaultdict(float)
        self._pricing_stats: dict[str, float] = {"lookups": 0.0, "cache_hits": 0.0}
        self._drift: dict[tuple[str, str], float] = {}

    # ------------------------------------------------------------- ingestion

    def update(self, costs: list[ResourceCost],
               groups: list[tuple[str, str, str]] | None = None) -> None:
        """Replace the snapshot for every (account, region, service) present in
        ``costs``. Groups absent from this batch keep their previous values, so a
        partial collection pass never blanks out unrelated services.

        ``groups`` lets a caller declare which (account, region, service) triples the
        pass covered even when it found nothing - that is how a service whose last
        resource was deleted drops to zero immediately instead of waiting out
        STALE_AFTER.
        """
        now = time.time()
        shaped = self._apply_cardinality_caps(costs)

        with self._lock:
            # 1. Bring every known series up to now at the rate that was in effect
            #    over the interval that just elapsed. Doing this for all series, not
            #    just the ones in this batch, keeps the integral continuous when
            #    estimators run on different cadences.
            for key, last in self._seen.items():
                self._totals[key] += self._rates.get(key, 0.0) * (now - last) / 3600.0
                self._seen[key] = now

            # 2. Zero the groups this pass covers. Anything still alive is re-set in
            #    step 3; anything that vanished correctly drops to a zero rate rather
            #    than freezing at its last value forever.
            touched = {(c.account_id, c.region, c.service) for c in shaped}
            touched.update(groups or [])
            for key in self._rates:
                if (key[0], key[2], key[3]) in touched:
                    self._rates[key] = 0.0

            # 3. Apply this pass.
            for cost in shaped:
                key = tuple(cost.label_values(self.tag_keys)[label]
                            for label in self._labels)
                self._rates[key] = cost.usd_per_hour
                self._seen.setdefault(key, now)
                self._reported[key] = now
                # Publish the counter at zero from the moment a resource is first
                # seen. Without this the series only appears on the second pass, and
                # increase() over a window starting at the resource's birth silently
                # misses its first interval.
                self._totals.setdefault(key, 0.0)

            # 4. Forget series nothing has reported in a long time, so a deleted
            #    resource eventually stops occupying a Prometheus series.
            for key, last in list(self._reported.items()):
                if now - last > STALE_AFTER:
                    self._reported.pop(key, None)
                    self._seen.pop(key, None)
                    self._rates.pop(key, None)
                    self._totals.pop(key, None)

    def _apply_cardinality_caps(self, costs: list[ResourceCost]) -> list[ResourceCost]:
        groups: dict[tuple, list[ResourceCost]] = defaultdict(list)
        for c in costs:
            groups[(c.account_id, c.region, c.service, c.dimension)].append(c)

        shaped: list[ResourceCost] = []
        for (account_id, region, service, dimension), items in groups.items():
            keep, spill = [], []
            for c in items:
                (keep if c.usd_per_hour >= self.min_usd_per_hour else spill).append(c)

            keep.sort(key=lambda c: c.usd_per_hour, reverse=True)
            if len(keep) > self.top_n:
                spill.extend(keep[self.top_n:])
                keep = keep[: self.top_n]

            shaped.extend(keep)
            if spill:
                sample = spill[0]
                shaped.append(ResourceCost(
                    account_id=account_id,
                    account_name=sample.account_name,
                    region=region,
                    service=service,
                    resource_type=sample.resource_type,
                    resource_id=OTHER,
                    usd_per_hour=sum(c.usd_per_hour for c in spill),
                    tier=sample.tier,
                    dimension=dimension,
                ))
        return shaped

    # ------------------------------------------------- operational telemetry

    def record_collection(self, estimator: str, account: str, region: str,
                          duration: float, ok: bool) -> None:
        key = (estimator, account, region)
        with self._lock:
            self._collections[key] += 1
            self._durations[key] = duration
            if ok:
                self._last_success[key] = time.time()
            else:
                self._errors[key] += 1

    def record_pricing_fallback(self, service: str, price_key: str) -> None:
        with self._lock:
            self._pricing_fallbacks[(service, price_key)] += 1

    def record_pricing_stats(self, lookups: float, cache_hits: float) -> None:
        with self._lock:
            self._pricing_stats["lookups"] = lookups
            self._pricing_stats["cache_hits"] = cache_hits

    def record_drift(self, account: str, service: str, ratio: float) -> None:
        with self._lock:
            self._drift[(account, service)] = ratio

    # ------------------------------------------------------------- exposition

    def collect(self):
        with self._lock:
            rates = dict(self._rates)
            totals = dict(self._totals)
            collections = dict(self._collections)
            errors = dict(self._errors)
            durations = dict(self._durations)
            last_success = dict(self._last_success)
            fallbacks = dict(self._pricing_fallbacks)
            pricing = dict(self._pricing_stats)
            drift = dict(self._drift)

        gauge = GaugeMetricFamily(
            "cloudlens_resource_usd_per_hour",
            "Current burn rate of one AWS resource, in USD per hour",
            labels=list(self._labels),
        )
        for key, value in rates.items():
            gauge.add_metric(list(key), value)
        yield gauge

        counter = CounterMetricFamily(
            "cloudlens_resource_usd",
            "Cumulative USD attributed to one AWS resource since collector start",
            labels=list(self._labels),
        )
        for key, value in totals.items():
            counter.add_metric(list(key), value)
        yield counter

        op_labels = ["estimator", "account_id", "region"]

        c = CounterMetricFamily("cloudlens_collections",
                                "Estimator collection passes attempted", labels=op_labels)
        for key, value in collections.items():
            c.add_metric(list(key), value)
        yield c

        e = CounterMetricFamily("cloudlens_collection_errors",
                                "Estimator collection passes that failed", labels=op_labels)
        for key, value in errors.items():
            e.add_metric(list(key), value)
        yield e

        d = GaugeMetricFamily("cloudlens_collection_duration_seconds",
                              "Duration of the last collection pass", labels=op_labels)
        for key, value in durations.items():
            d.add_metric(list(key), value)
        yield d

        s = GaugeMetricFamily("cloudlens_last_success_timestamp_seconds",
                              "Unix time of the last successful collection", labels=op_labels)
        for key, value in last_success.items():
            s.add_metric(list(key), value)
        yield s

        f = CounterMetricFamily(
            "cloudlens_pricing_fallback",
            "Times a pinned fallback price was used because the Pricing API returned "
            "nothing. Sustained non-zero values mean the reported cost is drifting "
            "from list price.",
            labels=["service", "price_key"],
        )
        for key, value in fallbacks.items():
            f.add_metric(list(key), value)
        yield f

        pl = CounterMetricFamily("cloudlens_pricing_api_lookups",
                                 "Calls made to the AWS Pricing API")
        pl.add_metric([], pricing.get("lookups", 0.0))
        yield pl

        pc = CounterMetricFamily("cloudlens_pricing_cache_hits",
                                 "Price lookups served from cache")
        pc.add_metric([], pricing.get("cache_hits", 0.0))
        yield pc

        dr = GaugeMetricFamily(
            "cloudlens_estimate_drift_ratio",
            "Derived estimate divided by the Cost Explorer actual for the same service "
            "and day. 1.0 is perfect; below 1.0 usually means an RI or Savings Plan "
            "discount the estimator cannot see.",
            labels=["account_id", "service"],
        )
        for key, value in drift.items():
            dr.add_metric(list(key), value)
        yield dr


def build_registry(cost_registry: CostRegistry) -> CollectorRegistry:
    registry = CollectorRegistry()
    registry.register(cost_registry)
    return registry
