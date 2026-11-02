"""Small flat-rate services that quietly accumulate: Secrets Manager, KMS.

Neither is expensive per unit. Both are expensive per *forgotten* unit - a few hundred
abandoned secrets or customer-managed keys is a real four-figure annual line, and
neither shows up in any per-resource view AWS ships.
"""
from __future__ import annotations

import logging
from typing import Iterable

from ..base import Context, Estimator, register, safe
from ..models import ResourceCost, Tier
from ._util import HOURS_PER_MONTH, priced, tags_of

log = logging.getLogger(__name__)


@register
class SecretsManagerEstimator(Estimator):
    name = "secretsmanager"
    tier = Tier.INVENTORY
    cadence = "inventory"
    required_actions = ("secretsmanager:ListSecrets",)

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        secrets = safe(
            lambda: list(ctx.paginate("secretsmanager", "list_secrets", "SecretList")),
            [], "secretsmanager:ListSecrets " + ctx.region,
        )
        if not secrets:
            return []
        monthly = priced(
            ctx.pricing.price("AWSSecretsManager", {"productFamily": "Secret"},
                              region=ctx.region, unit_hint="Secrets"),
            "secretsmanager.secret_month", "secretsmanager",
        )
        return [
            ctx.cost(service="secretsmanager", resource_type="secret",
                     resource_id=s["Name"],
                     usd_per_hour=monthly / HOURS_PER_MONTH,
                     tier=Tier.INVENTORY, dimension="storage",
                     tags=tags_of(s.get("Tags"), ctx.tag_keys))
            for s in secrets
        ]


@register
class KmsEstimator(Estimator):
    """Only customer-managed keys are billed; AWS-managed keys are free and are
    filtered out by KeyManager."""

    name = "kms"
    tier = Tier.INVENTORY
    cadence = "inventory"
    required_actions = ("kms:ListKeys", "kms:DescribeKey")

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        keys = safe(
            lambda: list(ctx.paginate("kms", "list_keys", "Keys")),
            [], "kms:ListKeys " + ctx.region,
        )
        if not keys:
            return []
        kms = ctx.client("kms")
        monthly = priced(
            ctx.pricing.price("awskms", {"usagetype": "KMS-Keys"},
                              region=ctx.region, unit_hint="Keys"),
            "kms.key_month", "kms",
        )

        out: list[ResourceCost] = []
        for key in keys:
            meta = safe(
                lambda k=key["KeyId"]: kms.describe_key(KeyId=k)["KeyMetadata"],
                None, "kms:DescribeKey",
            )
            if not meta or meta.get("KeyManager") != "CUSTOMER":
                continue
            if meta.get("KeyState") in {"PendingDeletion", "Unavailable"}:
                continue
            out.append(ctx.cost(
                service="kms", resource_type="key",
                resource_id=meta.get("Description") or meta["KeyId"],
                usd_per_hour=monthly / HOURS_PER_MONTH,
                tier=Tier.INVENTORY, dimension="key"))
        return out
