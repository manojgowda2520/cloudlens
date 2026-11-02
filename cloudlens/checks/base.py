"""Check contract and the per-account view checks run against.

A check is a small function over one account's inventory from one scan. It yields a
`Hit` per failing resource, with evidence - the exact field and value that failed -
so a finding can be verified without opening the console.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional

log = logging.getLogger(__name__)


@dataclass
class Finding:
    check_id: str
    arn: str
    account_id: str
    region: str
    severity: str
    title: str
    evidence: str
    remediation: str
    source: str = "cloudlens"


@dataclass
class Hit:
    item: Any                       # a resource dict from View, or an ARN string
    evidence: str
    severity: Optional[str] = None  # overrides the check's default
    title: Optional[str] = None     # overrides the check's default (imported findings)
    remediation: Optional[str] = None


@dataclass
class Check:
    id: str
    severity: str
    title: str
    remediation: str
    area: str
    fn: Callable[["View"], Iterable[Hit]]


_REGISTRY: dict[str, Check] = {}


def check(id: str, severity: str, title: str, remediation: str):
    def wrap(fn):
        area = fn.__module__.rsplit(".", 1)[-1]
        if id in _REGISTRY:
            raise ValueError(f"duplicate check id {id}")
        _REGISTRY[id] = Check(id, severity, title, remediation, area, fn)
        return fn
    return wrap


def checks() -> dict[str, Check]:
    from . import compute, data, dns, identity, logging_, network, storage  # noqa: F401
    return dict(_REGISTRY)


@dataclass
class Shared:
    """Facts across every account in the scan, for checks that look outside one account
    (dangling DNS needs to know every bucket and distribution cloudlens can see)."""

    bucket_names: set = field(default_factory=set)
    cloudfront_domains: set = field(default_factory=set)
    beanstalk_cnames: set = field(default_factory=set)
    elb_dns_names: set = field(default_factory=set)
    account_ids: set = field(default_factory=set)


class View:
    def __init__(self, account_id: str, resources: list[dict], shared: Optional[Shared] = None,
                 now: Optional[datetime] = None):
        self.account_id = account_id
        self.resources = resources
        self.shared = shared or Shared()
        self.now = now or datetime.now(timezone.utc)
        self._by_type: dict[tuple[str, str], list[dict]] = {}
        for r in resources:
            self._by_type.setdefault((r["service"], r["type"]), []).append(r)

    @classmethod
    def from_rows(cls, account_id: str, rows, shared: Optional[Shared] = None) -> "View":
        resources = []
        for row in rows:
            r = dict(row)
            r["raw"] = json.loads(r["raw"]) if isinstance(r.get("raw"), str) else (r.get("raw") or {})
            r["tags"] = json.loads(r["tags"]) if isinstance(r.get("tags"), str) else (r.get("tags") or {})
            resources.append(r)
        return cls(account_id, resources, shared)

    def of(self, service: str, type_: str) -> list[dict]:
        return self._by_type.get((service, type_), [])

    def account(self) -> Optional[dict]:
        found = self.of("account", "account")
        return found[0] if found else None

    def regions_in_use(self) -> set:
        return {r["region"] for r in self.resources
                if r["region"] != "global" and r["service"] != "account"}

    def days_since(self, value: Any) -> Optional[float]:
        dt = parse_time(value)
        return (self.now - dt).total_seconds() / 86400 if dt else None


def parse_time(value: Any) -> Optional[datetime]:
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000 if value > 1e11 else value, tz=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def run_checks(view: View, only: Optional[Iterable[str]] = None) -> list[Finding]:
    """Run every check (or `only` these) and return findings. A check that raises is
    logged and skipped - one buggy check must not hide the results of the rest."""
    out: list[Finding] = []
    wanted = set(only) if only else None
    for c in checks().values():
        if wanted and c.id not in wanted:
            continue
        try:
            hits = list(c.fn(view))
        except Exception:  # noqa: BLE001
            log.exception("check %s failed for %s", c.id, view.account_id)
            continue
        for h in hits:
            item = h.item
            arn = item["arn"] if isinstance(item, dict) else str(item)
            region = item.get("region", "global") if isinstance(item, dict) else "global"
            out.append(Finding(
                check_id=c.id, arn=arn, account_id=view.account_id, region=region,
                severity=h.severity or c.severity, title=h.title or c.title, evidence=h.evidence,
                remediation=h.remediation or c.remediation,
                source="aws" if c.id.startswith("AWS-") else "cloudlens",
            ))
    return out
