"""The scan: every enabled account x region x collector, then checks and cost.

Work fans out across a thread pool at (account, region) granularity - collectors for
one region run in sequence, which keeps per-service request rates polite while still
covering many regions at once. Results are written as each unit finishes, so a scan
that dies part-way still leaves usable data behind.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import guard
from .accounts import AccountSession
from .checks.base import Shared, View, run_checks
from .config import AccountConfig
from .cost import explorer
from .inventory import regional
from .inventory.base import Ctx, collectors
from .sso import LoginRequired, Portal, SSOSource
from .store import Store

log = logging.getLogger(__name__)

MODULES = ("inventory", "security", "cost", "resource-cost")
DEFAULT_MODULES = ("inventory", "security", "cost")


@dataclass
class Progress:
    scan_id: int = 0
    total: int = 0
    done: int = 0
    phase: str = "starting"
    running: bool = False
    started: float = 0.0
    log: list = field(default_factory=list)

    def note(self, msg: str) -> None:
        self.log.append((time.time(), msg))
        del self.log[:-50]


def home_region(region: str) -> str:
    return "cn-north-1" if region.startswith("cn-") else "us-gov-west-1" if region.startswith("us-gov-") else "us-east-1"


class Scanner:
    def __init__(self, store: Store, portals: dict[str, Portal], audit: guard.AuditLog,
                 workers: int = 16):
        self.store = store
        self.portals = portals
        self.audit = audit
        self.workers = workers
        self.progress = Progress()
        self._lock = threading.Lock()

    # ------------------------------------------------------------ sessions

    def session_for(self, account) -> AccountSession:
        portal = self.portals[account["portal_id"]]
        source = SSOSource(portal, account["account_id"], account["role_name"])
        return AccountSession(AccountConfig(account_id=account["account_id"], name=account["name"]),
                              source=source, audit=self.audit)

    def regions_for(self, account, session: AccountSession, errors: list) -> list[str]:
        if account["regions"]:
            return json.loads(account["regions"])
        ec2 = session.client("ec2", home_region(self.portals[account["portal_id"]].region))
        try:
            return sorted(r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"])
        except Exception as exc:  # noqa: BLE001
            errors.append((account["account_id"], "global", "regions", f"{type(exc).__name__}: {exc}"))
            return []

    # ----------------------------------------------------------------- run

    def run(self, modules=DEFAULT_MODULES, account_ids: Optional[list[str]] = None,
            force_cost: bool = False, on_progress: Optional[Callable[[Progress], None]] = None) -> int:
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("a scan is already running")
        try:
            return self._run(list(modules), account_ids, force_cost)
        finally:
            self.progress.running = False
            self.audit.flush()
            self._lock.release()

    def _run(self, modules: list[str], account_ids, force_cost: bool) -> int:
        store = self.store
        accounts = [a for a in store.accounts(enabled_only=True)
                    if not account_ids or a["account_id"] in account_ids]
        scan_id = store.start_scan(modules)
        p = self.progress = Progress(scan_id=scan_id, running=True, started=time.time())
        p.note(f"scan {scan_id}: {len(accounts)} accounts, modules {', '.join(modules)}")
        errors: list[tuple] = []

        sessions = {}
        for a in accounts:
            if not a["role_name"]:
                errors.append((a["account_id"], "global", "auth", "no role selected for this account"))
                continue
            try:
                s = self.session_for(a)
                s.session()   # fail fast on expired SSO
                sessions[a["account_id"]] = (a, s)
            except LoginRequired as exc:
                errors.append((a["account_id"], "global", "auth", str(exc)))
            except Exception as exc:  # noqa: BLE001
                errors.append((a["account_id"], "global", "auth", f"{type(exc).__name__}: {exc}"))

        try:
            if "inventory" in modules:
                self._inventory(scan_id, sessions, errors)
            if "security" in modules:
                p.phase = "security checks"
                self._security(scan_id, list(sessions))
            if "cost" in modules:
                p.phase = "cost"
                self._cost(sessions, errors, force_cost)
            if "resource-cost" in modules:
                p.phase = "per-resource cost"
                self._resource_cost(scan_id, sessions, errors)
        except Exception as exc:  # noqa: BLE001
            log.exception("scan %s failed", scan_id)
            store.add_scan_errors(scan_id, errors)
            store.finish_scan(scan_id, "failed", f"{type(exc).__name__}: {exc}")
            p.note(f"failed: {exc}")
            return scan_id

        store.add_scan_errors(scan_id, errors)
        status = "partial" if errors or not sessions else "ok"
        store.finish_scan(scan_id, status, f"{len(sessions)}/{len(accounts)} accounts reachable")
        store.prune()
        p.phase = "done"
        p.note(f"scan {scan_id} {status}: {len(errors)} errors")
        return scan_id

    # ----------------------------------------------------------- inventory

    def _inventory(self, scan_id: int, sessions: dict, errors: list) -> None:
        p = self.progress
        p.phase = "listing regions"
        units = []
        for _acct_id, (a, s) in sessions.items():
            home = home_region(self.portals[a["portal_id"]].region)
            units.append((s, "global", home))
            for r in self.regions_for(a, s, errors):
                units.append((s, r, home))
        p.total, p.done, p.phase = len(units), 0, "inventory"
        all_cols = collectors()
        global_cols = [c for c in all_cols.values() if c.scope == "global"]
        regional_cols = [c for c in all_cols.values() if c.scope == "regional"]

        def unit(session: AccountSession, region: str, home: str):
            ctx = Ctx(session, region, home)
            found = []
            for col in (global_cols if region == "global" else regional_cols):
                ctx.collector = col.name
                try:
                    found.extend(col.fn(ctx))
                except Exception as exc:  # noqa: BLE001 - a collector bug must not end the scan
                    log.exception("collector %s failed", col.name)
                    ctx.errors.append((session.account_id, region, col.name, f"{type(exc).__name__}: {exc}"))
            if region != "global":
                ctx.collector = "tagging"
                seen = {r.arn for r in found}
                for item in regional.tagged_resources(ctx):
                    if item["ResourceARN"] not in seen:
                        found.append(regional.generic(ctx, item))
            return found, ctx.errors

        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="scan") as pool:
            futures = {pool.submit(unit, *u): u for u in units}
            for fut in as_completed(futures):
                s, region, _ = futures[fut]
                try:
                    found, errs = fut.result()
                except Exception as exc:  # noqa: BLE001
                    found, errs = [], [(s.account_id, region, "scan", str(exc))]
                self.store.add_resources(scan_id, found)
                errors.extend(errs)
                p.done += 1
                if found:
                    p.note(f"{s.name} {region}: {len(found)} resources")

    # ------------------------------------------------------------ security

    def _shared(self, scan_id: int) -> Shared:
        sh = Shared(account_ids={a["account_id"] for a in self.store.accounts()})
        for row in self.store.q("SELECT service, type, name, raw FROM resources WHERE scan_id=? AND "
                                "type IN ('bucket','distribution','environment','application','network','classic')",
                                (scan_id,)):
            raw = json.loads(row["raw"])
            if row["type"] == "bucket":
                sh.bucket_names.add(row["name"])
            elif row["type"] == "distribution":
                sh.cloudfront_domains.add(raw.get("DomainName", "").lower())
            elif row["type"] == "environment":
                if raw.get("CNAME"):
                    sh.beanstalk_cnames.add(raw["CNAME"].lower())
            elif raw.get("DNSName"):
                sh.elb_dns_names.add(raw["DNSName"].lower())
        return sh

    def _security(self, scan_id: int, account_ids: list[str]) -> None:
        shared = self._shared(scan_id)
        for acct in account_ids:
            view = View.from_rows(acct, self.store.resources(scan_id, acct), shared)
            findings = run_checks(view)
            self.store.add_findings(scan_id, findings)
            self.progress.note(f"{acct}: {len(findings)} findings")

    # ---------------------------------------------------------------- cost

    def _cost(self, sessions: dict, errors: list, force: bool) -> None:
        for acct, (a, s) in sessions.items():
            if not force and time.time() - self.store.cost_fetched_at(acct) < explorer.CACHE_SECONDS:
                continue
            try:
                daily, forecast = explorer.fetch(s)
                self.store.save_cost(acct, daily, forecast)
                self.progress.note(f"{a['name']}: cost updated")
            except Exception as exc:  # noqa: BLE001
                msg = f"{type(exc).__name__}: {exc}"
                errors.append((acct, "us-east-1", "cost", msg))
                self.store.save_cost(acct, [], None, msg)

    def _resource_cost(self, scan_id: int, sessions: dict, errors: list) -> None:
        """Run the per-resource cost estimators once and keep their $/hour rates."""
        import boto3

        from .cost.base import Context, select
        from .cost.estimators import _util  # noqa: F401
        from .cost.pricing import PricingClient
        from . import paths
        pricing = PricingClient(guard.protect(boto3.Session(), audit=self.audit), str(paths.pricing_cache()))
        estimators = [e for e in select(["*"], ["cost_explorer"])]
        regions = {r["account_id"]: sorted({x["region"] for x in self.store.q(
            "SELECT DISTINCT region FROM resources WHERE scan_id=? AND account_id=? AND region!='global'",
            (scan_id, r["account_id"]))}) for r in self.store.accounts(enabled_only=True)}
        rows = []
        for acct, (_a, s) in sessions.items():
            for est in estimators:
                for region in (["us-east-1"] if est.global_service else regions.get(acct, [])):
                    try:
                        for c in est.collect(Context(session=s, region=region, pricing=pricing)):
                            rows.append((acct, c.region, c.service, c.resource_id, c.usd_per_hour, c.tier.value))
                    except Exception as exc:  # noqa: BLE001
                        errors.append((acct, region, f"cost:{est.name}", f"{type(exc).__name__}: {exc}"))
        self.store.add_resource_costs(scan_id, rows)
