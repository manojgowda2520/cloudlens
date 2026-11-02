"""CloudWatch itself - routinely a top-five line item and almost never watched.

Log ingestion is billed per GB at roughly 17x the rate of storing that same GB for a
month, so a single chatty log group can outweigh the fleet producing it. IncomingBytes
is a per-log-group 1-minute metric, which makes the expensive half of this fully
realtime.
"""
from __future__ import annotations

import logging
from typing import Iterable

from ..base import Context, Estimator, register, safe
from ..cloudwatch import MetricQuery
from ..models import ResourceCost, Tier
from ._util import GB, HOURS_PER_MONTH, priced

log = logging.getLogger(__name__)


@register
class CloudWatchLogsEstimator(Estimator):
    name = "cloudwatch_logs"
    tier = Tier.REALTIME
    cadence = "realtime"
    required_actions = ("logs:DescribeLogGroups", "cloudwatch:GetMetricData")

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        groups = safe(
            lambda: list(ctx.paginate("logs", "describe_log_groups", "logGroups")),
            [], "logs:DescribeLogGroups " + ctx.region,
        )
        if not groups:
            return []

        ingest_gb = priced(
            ctx.pricing.price("AmazonCloudWatch",
                              {"productFamily": "Data Payload"},
                              region=ctx.region, unit_hint="GB"),
            "logs.ingest_gb", "cloudwatch_logs",
        )
        storage_gb_month = priced(
            ctx.pricing.price("AmazonCloudWatch",
                              {"productFamily": "Storage Snapshot"},
                              region=ctx.region, unit_hint="GB-Mo"),
            "logs.storage_gb_month", "cloudwatch_logs",
        )

        queries = [
            MetricQuery("in::" + g["logGroupName"], "AWS/Logs", "IncomingBytes",
                        {"LogGroupName": g["logGroupName"]})
            for g in groups
        ]
        data = ctx.metrics().read(queries)

        out: list[ResourceCost] = []
        for g in groups:
            name = g["logGroupName"]

            gb_hr = data.get("in::" + name, 0.0) / GB
            if gb_hr > 0:
                out.append(ctx.cost(
                    service="cloudwatch_logs", resource_type="log_group",
                    resource_id=name, usd_per_hour=gb_hr * ingest_gb,
                    tier=Tier.REALTIME, dimension="ingestion"))

            stored_gb = g.get("storedBytes", 0) / GB
            if stored_gb > 0:
                out.append(ctx.cost(
                    service="cloudwatch_logs", resource_type="log_group",
                    resource_id=name,
                    usd_per_hour=stored_gb * storage_gb_month / HOURS_PER_MONTH,
                    tier=Tier.INVENTORY, dimension="storage"))
        return out
