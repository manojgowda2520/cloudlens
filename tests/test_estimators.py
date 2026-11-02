"""Estimator tests using stubbed AWS clients.

The point of these is the *arithmetic* - that GB-seconds, GB-months and per-request
maths turn into the right dollars - not that boto3 works.
"""
from __future__ import annotations

import pytest

from cloudlens.cost.base import Context, registry
from cloudlens.cost.estimators.compute import EbsEstimator, LambdaEstimator
from cloudlens.cost.estimators.observability import CloudWatchLogsEstimator
from cloudlens.cost.models import Tier


class FakePricing:
    def __init__(self, prices: dict):
        self.prices = prices
        self.lookups = 0
        self.cache_hits = 0

    def price(self, service_code, filters, *, region=None, unit_hint=None):
        self.lookups += 1
        for (code, marker), value in self.prices.items():
            if code == service_code and marker in str(filters):
                return value
        return None


class FakeSession:
    def __init__(self, clients: dict):
        self._clients = clients
        self.name = "test"

    @property
    def account_id(self):
        return "111111111111"

    def client(self, service, region=None):
        return self._clients[service]


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return self._pages


class FakeClient:
    def __init__(self, pages: dict, **methods):
        self._pages = pages
        for name, value in methods.items():
            setattr(self, name, value)

    def get_paginator(self, operation):
        return FakePaginator(self._pages[operation])


def make_ctx(clients: dict, prices: dict) -> Context:
    return Context(
        session=FakeSession(clients),
        region="us-east-1",
        pricing=FakePricing(prices),
        window=3600,
    )


# --------------------------------------------------------------------- lambda

def test_lambda_cost_is_requests_plus_gb_seconds():
    """1M invocations/hr of a 1024 MB function averaging 1000 ms.

    requests: 1e6 * $0.0000002              = $0.20/hr
    duration: 1e6 s * 1 GB * $0.0000166667  = $16.67/hr
    """
    cw = FakeClient({}, get_metric_data=lambda **kw: {
        "MetricDataResults": [
            {
                "Id": q["Id"],
                "Values": [1_000_000.0 / 60] if q["MetricStat"]["Metric"]["MetricName"]
                == "Invocations" else [1_000_000_000.0 / 60],
            }
            for q in kw["MetricDataQueries"]
        ]
    })
    lam = FakeClient(
        {"list_functions": [{"Functions": [{
            "FunctionName": "checkout-api",
            "FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:checkout-api",
            "MemorySize": 1024,
            "Architectures": ["x86_64"],
        }]}]},
        list_tags=lambda Resource: {"Tags": {}},
    )
    ctx = make_ctx({"lambda": lam, "cloudwatch": cw}, {
        ("AWSLambda", "Requests"): 0.0000002,
        ("AWSLambda", "Duration"): 0.0000166667,
    })

    costs = list(LambdaEstimator().collect(ctx))
    by_dim = {c.dimension: c for c in costs}

    assert by_dim["requests"].usd_per_hour == pytest.approx(0.20, rel=1e-3)
    assert by_dim["duration"].usd_per_hour == pytest.approx(16.667, rel=1e-3)
    assert by_dim["duration"].resource_id == "checkout-api"
    assert by_dim["duration"].tier is Tier.REALTIME


def test_lambda_arm64_uses_the_cheaper_rate():
    cw = FakeClient({}, get_metric_data=lambda **kw: {
        "MetricDataResults": [
            {"Id": q["Id"],
             "Values": [] if q["MetricStat"]["Metric"]["MetricName"] == "Invocations"
             else [3_600_000.0 / 60]}
            for q in kw["MetricDataQueries"]
        ]
    })
    lam = FakeClient(
        {"list_functions": [{"Functions": [{
            "FunctionName": "graviton-fn",
            "FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:graviton-fn",
            "MemorySize": 1024,
            "Architectures": ["arm64"],
        }]}]},
        list_tags=lambda Resource: {"Tags": {}},
    )
    ctx = make_ctx({"lambda": lam, "cloudwatch": cw}, {
        ("AWSLambda", "Duration-ARM"): 0.0000133334,
        ("AWSLambda", "Duration"): 0.0000166667,
    })

    costs = list(LambdaEstimator().collect(ctx))
    duration = next(c for c in costs if c.dimension == "duration")

    # 3600 GB-seconds/hr at the ARM rate.
    assert duration.usd_per_hour == pytest.approx(3600 * 0.0000133334, rel=1e-6)


def test_idle_function_is_not_reported():
    """A function with no traffic costs nothing and must not occupy a series."""
    cw = FakeClient({}, get_metric_data=lambda **kw: {
        "MetricDataResults": [{"Id": q["Id"], "Values": []}
                              for q in kw["MetricDataQueries"]]
    })
    lam = FakeClient(
        {"list_functions": [{"Functions": [{
            "FunctionName": "idle-fn",
            "FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:idle-fn",
            "MemorySize": 128, "Architectures": ["x86_64"],
        }]}]},
        list_tags=lambda Resource: {"Tags": {}},
    )
    ctx = make_ctx({"lambda": lam, "cloudwatch": cw}, {("AWSLambda", "Requests"): 0.0000002})

    assert list(LambdaEstimator().collect(ctx)) == []


# ------------------------------------------------------------------------ ebs

def test_gp3_bills_only_iops_above_the_included_baseline():
    """A 100 GiB gp3 at 5000 IOPS: 3000 are free, 2000 are billed."""
    ec2 = FakeClient({"describe_volumes": [{"Volumes": [{
        "VolumeId": "vol-0abc", "VolumeType": "gp3", "Size": 100,
        "Iops": 5000, "Throughput": 125,
    }]}]})
    ctx = make_ctx({"ec2": ec2}, {
        ("AmazonEC2", "'productFamily': 'Storage'"): 0.08,
        ("AmazonEC2", "System Operation"): 0.005,
    })

    costs = {c.dimension: c.usd_per_hour for c in EbsEstimator().collect(ctx)}

    assert costs["storage"] == pytest.approx(100 * 0.08 / 730)
    assert costs["iops"] == pytest.approx(2000 * 0.005 / 730)
    assert "throughput" not in costs, "125 MB/s is the included baseline"


def test_io2_bills_every_provisioned_iop():
    ec2 = FakeClient({"describe_volumes": [{"Volumes": [{
        "VolumeId": "vol-0def", "VolumeType": "io2", "Size": 50, "Iops": 4000,
    }]}]})
    ctx = make_ctx({"ec2": ec2}, {
        ("AmazonEC2", "'productFamily': 'Storage'"): 0.125,
        ("AmazonEC2", "System Operation"): 0.065,
    })

    costs = {c.dimension: c.usd_per_hour for c in EbsEstimator().collect(ctx)}

    assert costs["iops"] == pytest.approx(4000 * 0.065 / 730), "io2 has no free tier"


# ------------------------------------------------------------- cloudwatch logs

def test_log_group_splits_ingestion_from_storage():
    """Ingestion dominates: 1 GB ingested costs 17x what storing 1 GB for a month does."""
    one_gb_per_hour = (1024 ** 3) / 60
    cw = FakeClient(
        {"describe_log_groups": [{"logGroups": [
            {"logGroupName": "/aws/lambda/chatty", "storedBytes": 10 * 1024 ** 3},
        ]}]},
        get_metric_data=lambda **kw: {
            "MetricDataResults": [{"Id": q["Id"], "Values": [one_gb_per_hour]}
                                  for q in kw["MetricDataQueries"]]
        },
    )
    ctx = make_ctx({"logs": cw, "cloudwatch": cw}, {
        ("AmazonCloudWatch", "Data Payload"): 0.50,
        ("AmazonCloudWatch", "Storage Snapshot"): 0.03,
    })

    costs = {c.dimension: c for c in CloudWatchLogsEstimator().collect(ctx)}

    assert costs["ingestion"].usd_per_hour == pytest.approx(0.50, rel=1e-3)
    assert costs["ingestion"].tier is Tier.REALTIME
    assert costs["storage"].usd_per_hour == pytest.approx(10 * 0.03 / 730)
    assert costs["storage"].tier is Tier.INVENTORY


# -------------------------------------------------------------------- registry

def test_every_estimator_is_well_formed():
    for name, cls in registry().items():
        assert cls.name == name
        assert cls.cadence in {"realtime", "inventory", "billing"}
        assert cls.required_actions, f"{name} must declare its IAM actions"


def test_registry_covers_the_expensive_services():
    """A regression guard: these are the services that dominate a typical bill."""
    names = set(registry())
    for expected in ("lambda", "ec2", "ebs", "rds", "s3", "dynamodb",
                     "cloudwatch_logs", "natgateway", "elb", "cost_explorer"):
        assert expected in names
