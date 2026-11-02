"""Messaging and API surfaces: SQS, SNS, API Gateway, Kinesis, Step Functions.

Everything here is request-priced, which makes it the best-behaved category for
realtime derivation: the CloudWatch counter *is* the billing unit.
"""
from __future__ import annotations

import logging
from typing import Iterable

from ..base import Context, Estimator, register, safe
from ..cloudwatch import MetricQuery
from ..models import ResourceCost, Tier
from ._util import GB, priced

log = logging.getLogger(__name__)


@register
class SqsEstimator(Estimator):
    """SQS bills per request, where one request moves up to 64 KB. Sends, receives
    and deletes are all separately billable requests."""

    name = "sqs"
    tier = Tier.REALTIME
    cadence = "realtime"
    required_actions = ("sqs:ListQueues", "cloudwatch:GetMetricData")

    METRICS = ("NumberOfMessagesSent", "NumberOfMessagesReceived",
               "NumberOfMessagesDeleted")

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        urls = safe(
            lambda: list(ctx.paginate("sqs", "list_queues", "QueueUrls")),
            [], "sqs:ListQueues " + ctx.region,
        )
        if not urls:
            return []
        names = [u.rsplit("/", 1)[-1] for u in urls]

        queries = [
            MetricQuery(m + "::" + n, "AWS/SQS", m, {"QueueName": n})
            for n in names for m in self.METRICS
        ]
        data = ctx.metrics().read(queries)

        per_request = priced(
            ctx.pricing.price("AWSQueueService", {"group": "SQS-APIRequest-Standard"},
                              region=ctx.region, unit_hint="Requests"),
            "sqs.request", "sqs",
        )
        out: list[ResourceCost] = []
        for n in names:
            total = sum(data.get(m + "::" + n, 0.0) for m in self.METRICS)
            if total <= 0:
                continue
            out.append(ctx.cost(
                service="sqs", resource_type="queue", resource_id=n,
                usd_per_hour=total * per_request,
                tier=Tier.REALTIME, dimension="requests"))
        return out


@register
class SnsEstimator(Estimator):
    name = "sns"
    tier = Tier.REALTIME
    cadence = "realtime"
    required_actions = ("sns:ListTopics", "cloudwatch:GetMetricData")

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        topics = safe(
            lambda: [t["TopicArn"].rsplit(":", 1)[-1]
                     for t in ctx.paginate("sns", "list_topics", "Topics")],
            [], "sns:ListTopics " + ctx.region,
        )
        if not topics:
            return []

        queries = [
            MetricQuery("pub::" + t, "AWS/SNS", "NumberOfMessagesPublished",
                        {"TopicName": t})
            for t in topics
        ]
        data = ctx.metrics().read(queries)
        per_request = priced(
            ctx.pricing.price("AmazonSNS", {"group": "SNS-Requests-Tier1"},
                              region=ctx.region, unit_hint="Requests"),
            "sns.request", "sns",
        )
        return [
            ctx.cost(service="sns", resource_type="topic", resource_id=t,
                     usd_per_hour=data["pub::" + t] * per_request,
                     tier=Tier.REALTIME, dimension="requests")
            for t in topics if data.get("pub::" + t, 0.0) > 0
        ]


@register
class ApiGatewayEstimator(Estimator):
    """REST and HTTP APIs are priced an order of magnitude apart, so the two are
    looked up and labelled separately."""

    name = "apigateway"
    tier = Tier.REALTIME
    cadence = "realtime"
    required_actions = ("apigateway:GET", "cloudwatch:GetMetricData")

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        out: list[ResourceCost] = []

        rest = safe(
            lambda: list(ctx.paginate("apigateway", "get_rest_apis", "items")),
            [], "apigateway:GetRestApis " + ctx.region,
        )
        if rest:
            queries = [
                MetricQuery("c::" + a["name"], "AWS/ApiGateway", "Count",
                            {"ApiName": a["name"]})
                for a in rest
            ]
            data = ctx.metrics().read(queries)
            price = priced(
                ctx.pricing.price("AmazonApiGateway", {"group": "ApiGatewayRequest"},
                                  region=ctx.region, unit_hint="Requests"),
                "apigw.rest_request", "apigateway",
            )
            for a in rest:
                rate = data.get("c::" + a["name"], 0.0)
                if rate > 0:
                    out.append(ctx.cost(
                        service="apigateway", resource_type="rest_api",
                        resource_id=a["name"], usd_per_hour=rate * price,
                        tier=Tier.REALTIME, dimension="requests"))

        http = safe(
            lambda: list(ctx.paginate("apigatewayv2", "get_apis", "Items")),
            [], "apigatewayv2:GetApis " + ctx.region,
        )
        if http:
            queries = [
                MetricQuery("c::" + a["ApiId"], "AWS/ApiGateway", "Count",
                            {"ApiId": a["ApiId"], "Stage": "$default"})
                for a in http
            ]
            data = ctx.metrics().read(queries)
            price = priced(
                ctx.pricing.price("AmazonApiGateway", {"group": "ApiGatewayHttpApi"},
                                  region=ctx.region, unit_hint="Requests"),
                "apigw.http_request", "apigateway",
            )
            for a in http:
                rate = data.get("c::" + a["ApiId"], 0.0)
                if rate > 0:
                    out.append(ctx.cost(
                        service="apigateway", resource_type="http_api",
                        resource_id=a.get("Name") or a["ApiId"],
                        usd_per_hour=rate * price,
                        tier=Tier.REALTIME, dimension="requests"))
        return out


@register
class KinesisEstimator(Estimator):
    """Provisioned streams bill per shard-hour plus per PUT payload unit (25 KB)."""

    name = "kinesis"
    tier = Tier.REALTIME
    cadence = "realtime"
    required_actions = ("kinesis:ListStreams", "kinesis:DescribeStreamSummary",
                        "cloudwatch:GetMetricData")

    PUT_UNIT_BYTES = 25 * 1024

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        names = safe(
            lambda: list(ctx.paginate("kinesis", "list_streams", "StreamNames")),
            [], "kinesis:ListStreams " + ctx.region,
        )
        if not names:
            return []

        kinesis = ctx.client("kinesis")
        shard_hour = priced(
            ctx.pricing.price("AmazonKinesis", {"group": "Provisioned shard hour"},
                              region=ctx.region, unit_hint="Shard-Hour"),
            "kinesis.shard_hour", "kinesis",
        )
        put_unit = priced(
            ctx.pricing.price("AmazonKinesis", {"group": "Payload Units"},
                              region=ctx.region, unit_hint="PUT Payload Units"),
            "kinesis.put_unit", "kinesis",
        )

        queries = [
            MetricQuery("bytes::" + n, "AWS/Kinesis", "IncomingBytes",
                        {"StreamName": n})
            for n in names
        ]
        data = ctx.metrics().read(queries)

        out: list[ResourceCost] = []
        for n in names:
            summary = safe(
                lambda s=n: kinesis.describe_stream_summary(
                    StreamName=s)["StreamDescriptionSummary"],
                None, "kinesis:DescribeStreamSummary",
            )
            if not summary:
                continue
            if summary.get("StreamModeDetails", {}).get("StreamMode") != "ON_DEMAND":
                shards = summary.get("OpenShardCount", 0)
                if shards:
                    out.append(ctx.cost(
                        service="kinesis", resource_type="stream", resource_id=n,
                        usd_per_hour=shards * shard_hour,
                        tier=Tier.INVENTORY, dimension="shards"))

            bytes_hr = data.get("bytes::" + n, 0.0)
            if bytes_hr > 0:
                units_hr = bytes_hr / self.PUT_UNIT_BYTES
                out.append(ctx.cost(
                    service="kinesis", resource_type="stream", resource_id=n,
                    usd_per_hour=units_hr * put_unit,
                    tier=Tier.REALTIME, dimension="put_units"))
        return out
