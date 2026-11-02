"""Batched CloudWatch metric reads.

Every realtime estimator needs the same thing: "for each of these N resources, what
was the Sum/Average of metric M over the last window". Doing that as N GetMetricStatistics
calls throttles instantly at any real scale. GetMetricData takes up to 500 queries per
request, so this module batches, paginates and normalises the result into a flat dict.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

log = logging.getLogger(__name__)

MAX_QUERIES_PER_CALL = 450   # 500 is the hard limit; leave headroom


@dataclass(frozen=True)
class MetricQuery:
    key: str                       # caller's handle for the result
    namespace: str
    metric_name: str
    dimensions: dict[str, str]
    stat: str = "Sum"
    period: int = 60
    unit: str | None = None


class MetricReader:
    def __init__(self, cw_client, window_seconds: int = 300, lag_seconds: int = 120):
        """``lag_seconds`` skips the trailing window where CloudWatch data is still
        landing. Reading right up to *now* systematically under-reports."""
        self._cw = cw_client
        self.window = window_seconds
        self.lag = lag_seconds

    def read(self, queries: list[MetricQuery]) -> dict[str, float]:
        """Return {key: value}. Missing/absent metrics are simply absent from the dict.

        For Sum stats the value is normalised to a *per-hour rate* so callers can
        multiply straight by a unit price. For Average/Maximum the raw value is kept.
        """
        end = datetime.now(timezone.utc) - timedelta(seconds=self.lag)
        start = end - timedelta(seconds=self.window)
        out: dict[str, float] = {}

        for batch in _chunks(queries, MAX_QUERIES_PER_CALL):
            id_map = {f"q{i}": q for i, q in enumerate(batch)}
            spec = []
            for qid, q in id_map.items():
                metric = {
                    "Namespace": q.namespace,
                    "MetricName": q.metric_name,
                    "Dimensions": [{"Name": k, "Value": v} for k, v in q.dimensions.items()],
                }
                item = {
                    "Id": qid,
                    "MetricStat": {"Metric": metric, "Period": q.period, "Stat": q.stat},
                    "ReturnData": True,
                }
                if q.unit:
                    item["MetricStat"]["Unit"] = q.unit
                spec.append(item)

            token = None
            raw: dict[str, list[float]] = {}
            while True:
                kwargs = {
                    "MetricDataQueries": spec,
                    "StartTime": start,
                    "EndTime": end,
                    "ScanBy": "TimestampDescending",
                }
                if token:
                    kwargs["NextToken"] = token
                resp = self._cw.get_metric_data(**kwargs)
                for result in resp.get("MetricDataResults", []):
                    raw.setdefault(result["Id"], []).extend(result.get("Values", []))
                token = resp.get("NextToken")
                if not token:
                    break

            for qid, values in raw.items():
                if not values:
                    continue
                q = id_map[qid]
                if q.stat == "Sum":
                    # Sum over the datapoints we actually got back, scaled to an hourly
                    # rate by the span those datapoints cover - not by the nominal
                    # window, which would understate a metric that reports sparsely.
                    covered = max(len(values) * q.period, q.period)
                    out[q.key] = sum(values) * 3600.0 / covered
                else:
                    out[q.key] = sum(values) / len(values)
        return out


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]
