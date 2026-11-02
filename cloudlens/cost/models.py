"""Core data types shared by every estimator."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Tier(str, Enum):
    """Fidelity tier of a cost figure.

    REALTIME  - derived from CloudWatch usage metrics + Pricing API, ~1-2 min lag.
    INVENTORY - derived from a describe/list call + Pricing API. Exact rate, but the
                resource only has to exist to be billed, so lag is the describe interval.
    BILLING   - taken from Cost Explorer. Authoritative but 6-24h stale and, for most
                services, only resolvable down to the service (not the resource).
    """

    REALTIME = "realtime"
    INVENTORY = "inventory"
    BILLING = "billing"


@dataclass(frozen=True)
class ResourceCost:
    """The burn rate of one billable thing, at one instant.

    ``usd_per_hour`` is deliberately a *rate*, not an accumulated amount. The exporter
    integrates it into a counter, so a scrape that is missed or late never double-counts
    and never invents spend.
    """

    account_id: str
    account_name: str
    region: str
    service: str          # "lambda", "ec2", ... matches the estimator name
    resource_type: str    # "function", "instance", "volume", ...
    resource_id: str      # function name, i-0abc..., bucket name, ...
    usd_per_hour: float
    tier: Tier
    dimension: str = "all"          # "compute" / "requests" / "storage" - splits one
                                    # resource's bill into its priced components
    tags: dict[str, str] = field(default_factory=dict)

    def label_values(self, tag_keys: tuple[str, ...]) -> dict[str, str]:
        base = {
            "account_id": self.account_id,
            "account_name": self.account_name,
            "region": self.region,
            "service": self.service,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "dimension": self.dimension,
            "tier": self.tier.value,
        }
        for key in tag_keys:
            base[f"tag_{_sanitize(key)}"] = self.tags.get(key, "")
        return base


def _sanitize(key: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in key).strip("_").lower()
