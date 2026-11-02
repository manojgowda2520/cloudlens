"""Helpers shared across estimators."""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

GB = 1024 ** 3
HOURS_PER_MONTH = 730.0

# Last-resort unit prices, used only when the Pricing API returns nothing for a lookup
# (unsupported region, renamed attribute, throttle exhaustion). These are us-east-1
# public list prices and WILL drift - every use increments the
# cloudlens_pricing_fallback_total counter so you can see it happening in Grafana.
FALLBACK: dict[str, float] = {
    "lambda.request": 0.0000002,        # per request
    "lambda.gb_second": 0.0000166667,
    "lambda.gb_second_arm": 0.0000133334,
    "sqs.request": 0.0000004,
    "sns.request": 0.0000005,
    "apigw.rest_request": 0.0000035,
    "apigw.http_request": 0.000001,
    "logs.ingest_gb": 0.50,
    "logs.storage_gb_month": 0.03,
    "secretsmanager.secret_month": 0.40,
    "kms.key_month": 1.00,
    "route53.zone_month": 0.50,
    "route53.query": 0.0000004,
    "eks.cluster_hour": 0.10,
    "vpce.az_hour": 0.01,
    "natgw.hour": 0.045,
    "natgw.gb": 0.045,
    "ddb.rru": 0.000000125,
    "ddb.wru": 0.000000625,
    "ddb.storage_gb_month": 0.25,
    "s3.standard_gb_month": 0.023,
    "efs.gb_month": 0.30,
    "ecr.gb_month": 0.10,
    "cloudfront.gb": 0.085,
    "cloudfront.request": 0.0000010,
    "kinesis.shard_hour": 0.015,
    "kinesis.put_unit": 0.000000014,
}

_fallback_hook = None


def set_fallback_hook(fn) -> None:
    """Wired to the Prometheus counter by the exporter."""
    global _fallback_hook
    _fallback_hook = fn


def priced(value: float | None, fallback_key: str, service: str) -> float:
    """Return ``value``, or the pinned fallback price if the lookup came back empty."""
    if value is not None:
        return value
    if _fallback_hook:
        _fallback_hook(service, fallback_key)
    log.debug("using fallback price %s", fallback_key)
    return FALLBACK.get(fallback_key, 0.0)


def tags_of(raw: list[dict] | dict | None, wanted: list[str] | tuple[str, ...]) -> dict[str, str]:
    """Normalise the five different tag shapes AWS APIs return into a plain dict."""
    if not raw or not wanted:
        return {}
    if isinstance(raw, dict):
        pairs = raw.items()
    else:
        pairs = (
            (t.get("Key") or t.get("key"), t.get("Value") or t.get("value")) for t in raw
        )
    wanted_set = set(wanted)
    return {k: v for k, v in pairs if k in wanted_set and v is not None}
