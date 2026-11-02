"""The Sum-to-hourly-rate normalisation is the arithmetic every realtime estimator
depends on, so it gets its own tests."""
from __future__ import annotations

from cloudlens.cost.cloudwatch import MetricQuery, MetricReader


class FakeCloudWatch:
    """Minimal GetMetricData stub that replays canned values per query id."""

    def __init__(self, values: dict[str, list[float]]):
        self.values = values
        self.calls: list[dict] = []

    def get_metric_data(self, **kwargs):
        self.calls.append(kwargs)
        results = []
        for query in kwargs["MetricDataQueries"]:
            metric = query["MetricStat"]["Metric"]["MetricName"]
            results.append({"Id": query["Id"], "Values": self.values.get(metric, [])})
        return {"MetricDataResults": results}


def test_sum_is_scaled_to_an_hourly_rate():
    # 60 datapoints of 100 invocations at 60s each == one hour of data == 6000/hour.
    cw = FakeCloudWatch({"Invocations": [100.0] * 60})
    reader = MetricReader(cw, window_seconds=3600)

    out = reader.read([MetricQuery("k", "AWS/Lambda", "Invocations", {"FunctionName": "f"})])
    assert out["k"] == 6000.0


def test_sparse_metric_scales_by_covered_span_not_nominal_window():
    """Only 5 datapoints came back over a nominal 1h window.

    Dividing by the full hour would report the function as 12x cheaper than it is.
    The rate must reflect the span the data actually covers.
    """
    cw = FakeCloudWatch({"Invocations": [100.0] * 5})
    reader = MetricReader(cw, window_seconds=3600)

    out = reader.read([MetricQuery("k", "AWS/Lambda", "Invocations", {"FunctionName": "f"})])
    assert out["k"] == 6000.0


def test_average_stat_is_not_rate_scaled():
    cw = FakeCloudWatch({"BucketSizeBytes": [1000.0, 2000.0]})
    reader = MetricReader(cw, window_seconds=172800)

    out = reader.read([
        MetricQuery("k", "AWS/S3", "BucketSizeBytes", {"BucketName": "b"}, stat="Average")
    ])
    assert out["k"] == 1500.0


def test_absent_metric_is_omitted_not_zeroed():
    """An absent metric and a genuine zero are different facts; conflating them would
    make a resource look free rather than unmeasured."""
    cw = FakeCloudWatch({})
    reader = MetricReader(cw)

    out = reader.read([MetricQuery("k", "AWS/Lambda", "Invocations", {"FunctionName": "f"})])
    assert "k" not in out


def test_queries_are_batched_under_the_api_limit():
    cw = FakeCloudWatch({"Invocations": [1.0]})
    reader = MetricReader(cw)
    queries = [
        MetricQuery(f"k{i}", "AWS/Lambda", "Invocations", {"FunctionName": f"f{i}"})
        for i in range(1000)
    ]

    reader.read(queries)

    assert len(cw.calls) == 3, "1000 queries must not be one oversized request"
    assert all(len(c["MetricDataQueries"]) <= 500 for c in cw.calls)


def test_read_window_excludes_the_trailing_lag():
    """CloudWatch data lands late; reading right up to now under-reports."""
    cw = FakeCloudWatch({"Invocations": [1.0]})
    reader = MetricReader(cw, window_seconds=300, lag_seconds=120)

    reader.read([MetricQuery("k", "AWS/Lambda", "Invocations", {"FunctionName": "f"})])

    call = cw.calls[0]
    span = (call["EndTime"] - call["StartTime"]).total_seconds()
    assert span == 300
    from datetime import datetime, timezone
    behind = (datetime.now(timezone.utc) - call["EndTime"]).total_seconds()
    assert 115 < behind < 130
