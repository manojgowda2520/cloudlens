"""Money left on the table, read straight from the inventory.

Prices are us-east-1 list prices, rounded. The point is to rank what to clean up
first, not to reproduce the bill to the cent - every figure is shown as an estimate.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..checks.base import View

HOURS = 730

EBS_GB_MONTH = {"gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015,
                "standard": 0.05}
SNAPSHOT_GB_MONTH = 0.05
PUBLIC_IPV4_HOUR = 0.005
LB_HOUR = {"application": 0.0225, "network": 0.0225, "gateway": 0.0125, "classic": 0.025}
LOGS_GB_MONTH = 0.03


@dataclass
class Waste:
    account_id: str
    region: str
    arn: str
    name: str
    kind: str
    usd_month: float
    detail: str


def find(view: View) -> list[Waste]:
    out: list[Waste] = []

    def add(r: dict, kind: str, usd: float, detail: str) -> None:
        if usd >= 0.5:
            out.append(Waste(view.account_id, r["region"], r["arn"], r["name"], kind, round(usd, 2), detail))

    stopped = {i["raw"].get("InstanceId") for i in view.of("ec2", "instance")
               if (i["raw"].get("State") or {}).get("Name") == "stopped"}
    for v in view.of("ec2", "volume"):
        raw = v["raw"]
        price = EBS_GB_MONTH.get(raw.get("VolumeType", "gp3"), 0.08) * (raw.get("Size") or 0)
        if raw.get("State") == "available":
            add(v, "Unattached EBS volume", price, f"{raw.get('Size')} GB {raw.get('VolumeType')}, attached to nothing")
        elif any(a.get("InstanceId") in stopped for a in raw.get("Attachments") or []):
            add(v, "Volume on a stopped instance", price,
                f"{raw.get('Size')} GB {raw.get('VolumeType')} still billed while the instance is stopped")

    for a in view.of("ec2", "elastic-ip"):
        if not a["raw"].get("AssociationId"):
            add(a, "Idle Elastic IP", PUBLIC_IPV4_HOUR * HOURS, "allocated but not associated")

    for s in view.of("ec2", "snapshot"):
        age = view.days_since(s["raw"].get("StartTime"))
        if age and age > 180:
            add(s, "Old EBS snapshot", (s["raw"].get("VolumeSize") or 0) * SNAPSHOT_GB_MONTH,
                f"{int(age)} days old, from a {s['raw'].get('VolumeSize')} GB volume (upper bound - snapshots are incremental)")

    for t in ("application", "network", "gateway"):
        for lb in view.of("elbv2", t):
            if lb["raw"].get("TargetGroupCount", 1) == 0 or lb["raw"].get("TargetCount", 1) == 0:
                add(lb, "Load balancer with no targets", LB_HOUR[t] * HOURS, "no registered targets")
    for lb in view.of("elb", "classic"):
        if not lb["raw"].get("Instances"):
            add(lb, "Load balancer with no targets", LB_HOUR["classic"] * HOURS, "no registered instances")

    for g in view.of("logs", "log-group"):
        gb = (g["raw"].get("storedBytes") or 0) / 1e9
        if not g["raw"].get("retentionInDays") and gb >= 10:
            add(g, "Log group kept forever", gb * LOGS_GB_MONTH, f"{gb:.1f} GB stored, no retention set")

    return sorted(out, key=lambda w: -w.usd_month)


def total(items: Iterable[Waste]) -> float:
    return round(sum(w.usd_month for w in items), 2)
