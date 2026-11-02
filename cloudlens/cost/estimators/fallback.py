"""Cost Explorer fallback - the tier that guarantees nothing is missed.

The estimators in the other modules cover the services that dominate a real bill, but
AWS ships 200+ services and most of them publish no per-resource usage metric at all.
This estimator sweeps up *everything* at service granularity straight from the billing
system, so total coverage is complete even where per-resource attribution is not
possible.

Two things it is not: fast (6-24h behind) and free (each GetCostAndUsage call costs
$0.01, which is why it runs on its own slow cadence).

The upside is that it is the only source that reflects what you are *actually*
charged: Savings Plans, RIs, private pricing, credits and refunds all land here. That
makes it the yardstick reconcile.py measures the derived estimates against.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Iterable

from ..base import Context, Estimator, register, safe
from ..models import ResourceCost, Tier

log = logging.getLogger(__name__)

# CE service names -> the estimator that already covers them at higher fidelity.
# Anything not in this map is fallback-only, and is labelled as such so the dashboard
# can separate "we can drill into this" from "service level is all you get".
CE_SERVICE_MAP = {
    "AWS Lambda": "lambda",
    "Amazon Elastic Compute Cloud - Compute": "ec2",
    "EC2 - Other": "ebs",
    "Amazon Elastic Block Store": "ebs",
    "Amazon Relational Database Service": "rds",
    "Amazon DynamoDB": "dynamodb",
    "Amazon Simple Storage Service": "s3",
    "Amazon Elastic File System": "efs",
    "Amazon EC2 Container Registry (ECR)": "ecr",
    "Amazon Elastic Container Service": "fargate",
    "Amazon Elastic Container Service for Kubernetes": "eks",
    "Amazon Elastic Kubernetes Service": "eks",
    "Amazon ElastiCache": "elasticache",
    "Amazon OpenSearch Service": "opensearch",
    "Amazon Redshift": "redshift",
    "Amazon Simple Queue Service": "sqs",
    "Amazon Simple Notification Service": "sns",
    "Amazon API Gateway": "apigateway",
    "Amazon Kinesis": "kinesis",
    "AmazonCloudWatch": "cloudwatch_logs",
    "Amazon CloudFront": "cloudfront",
    "Amazon Route 53": "route53",
    "AWS Secrets Manager": "secretsmanager",
    "AWS Key Management Service": "kms",
    "Elastic Load Balancing": "elb",
}


@register
class CostExplorerEstimator(Estimator):
    name = "cost_explorer"
    tier = Tier.BILLING
    cadence = "billing"
    global_service = True
    required_actions = ("ce:GetCostAndUsage",)

    # UnblendedCost is what you are invoiced. AmortizedCost spreads RI/SP upfront fees
    # across the term, which is the more honest per-hour view but diverges from the
    # invoice; unblended is the safer default for a "what am I being charged" tool.
    METRIC = "UnblendedCost"

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        results = self._query(ctx, group_by_account=True)
        if results is None:
            # The org payer view is unavailable (not a payer account, or CE is not
            # enabled org-wide). Fall back to this account's own costs.
            results = self._query(ctx, group_by_account=False) or []

        out: list[ResourceCost] = []
        for period_hours, groups in results:
            for keys, amount in groups:
                if amount <= 0:
                    continue
                if len(keys) == 2:
                    account_id, service_name = keys
                else:
                    account_id, service_name = ctx.account_id, keys[0]

                covered_by = CE_SERVICE_MAP.get(service_name)
                out.append(ResourceCost(
                    account_id=account_id,
                    account_name=ctx.account_name if account_id == ctx.account_id
                    else account_id,
                    region="all",
                    service=covered_by or _slug(service_name),
                    resource_type="service",
                    resource_id=service_name,
                    usd_per_hour=amount / period_hours,
                    tier=Tier.BILLING,
                    dimension="realtime_covered" if covered_by else "fallback_only",
                ))
        return out

    def _query(self, ctx: Context, group_by_account: bool):
        """Return [(hours_in_period, [((keys...), amount), ...]), ...] or None."""
        ce = ctx.session.client("ce", "us-east-1")
        end = datetime.now(timezone.utc).date()
        start = end - timedelta(days=2)

        group_by = [{"Type": "DIMENSION", "Key": "SERVICE"}]
        if group_by_account:
            group_by.insert(0, {"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"})

        resp = safe(
            lambda: ce.get_cost_and_usage(
                TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
                Granularity="DAILY",
                Metrics=[self.METRIC],
                GroupBy=group_by,
            ),
            None,
            "ce:GetCostAndUsage" + (" (org)" if group_by_account else ""),
        )
        if resp is None:
            return None

        periods = resp.get("ResultsByTime", [])
        if not periods:
            return None

        # Use the most recent *complete* day. The current day is always partial and
        # would read as a spurious drop in spend.
        latest = periods[-1]
        groups = [
            (tuple(g["Keys"]), float(g["Metrics"][self.METRIC]["Amount"]))
            for g in latest.get("Groups", [])
        ]
        return [(24.0, groups)]


def _slug(service_name: str) -> str:
    cleaned = "".join(c if c.isalnum() else "_" for c in service_name.lower())
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    return cleaned.strip("_")
