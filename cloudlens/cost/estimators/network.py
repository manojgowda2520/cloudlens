"""Network: NAT gateways, load balancers, CloudFront, Route 53, VPC endpoints.

NAT gateway data processing and inter-AZ transfer are the classic "where did my bill
come from" line items, and unlike most data-transfer charges they *are* attributable
to a specific resource - which is what makes them worth modelling precisely.
"""
from __future__ import annotations

import logging
from typing import Iterable

from ..base import Context, Estimator, register, safe
from ..cloudwatch import MetricQuery
from ..models import ResourceCost, Tier
from ._util import GB, HOURS_PER_MONTH, priced, tags_of

log = logging.getLogger(__name__)


@register
class NatGatewayEstimator(Estimator):
    """Hourly charge plus per-GB data processing, per gateway."""

    name = "natgateway"
    tier = Tier.REALTIME
    cadence = "realtime"
    required_actions = ("ec2:DescribeNatGateways", "cloudwatch:GetMetricData")

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        gateways = safe(
            lambda: [g for g in ctx.paginate(
                "ec2", "describe_nat_gateways", "NatGateways")
                if g.get("State") == "available"],
            [], "ec2:DescribeNatGateways " + ctx.region,
        )
        if not gateways:
            return []

        hourly = priced(ctx.pricing.price(
            "AmazonEC2", {"productFamily": "NAT Gateway", "usagetype": "NatGateway-Hours"},
            region=ctx.region, unit_hint="Hrs"), "natgw.hour", "natgateway")
        per_gb = priced(ctx.pricing.price(
            "AmazonEC2", {"productFamily": "NAT Gateway", "usagetype": "NatGateway-Bytes"},
            region=ctx.region, unit_hint="GB"), "natgw.gb", "natgateway")

        queries = []
        for g in gateways:
            gid = g["NatGatewayId"]
            for metric in ("BytesOutToDestination", "BytesInFromDestination"):
                queries.append(MetricQuery(
                    metric + "::" + gid, "AWS/NATGateway", metric, {"NatGatewayId": gid}))
        data = ctx.metrics().read(queries)

        out: list[ResourceCost] = []
        for g in gateways:
            gid = g["NatGatewayId"]
            tags = tags_of(g.get("Tags"), ctx.tag_keys)
            out.append(ctx.cost(
                service="natgateway", resource_type="nat_gateway", resource_id=gid,
                usd_per_hour=hourly, tier=Tier.INVENTORY, dimension="hours", tags=tags))

            # Both directions are billed as processed bytes.
            processed_gb_hr = (
                data.get("BytesOutToDestination::" + gid, 0.0)
                + data.get("BytesInFromDestination::" + gid, 0.0)
            ) / GB
            if processed_gb_hr > 0:
                out.append(ctx.cost(
                    service="natgateway", resource_type="nat_gateway", resource_id=gid,
                    usd_per_hour=processed_gb_hr * per_gb,
                    tier=Tier.REALTIME, dimension="data_processing", tags=tags))
        return out


@register
class LoadBalancerEstimator(Estimator):
    """ALB/NLB hourly charge plus consumed LCUs, and Classic LB hours."""

    name = "elb"
    tier = Tier.REALTIME
    cadence = "realtime"
    required_actions = ("elasticloadbalancing:DescribeLoadBalancers",
                        "cloudwatch:GetMetricData")

    CONFIG = {
        "application": ("AWS/ApplicationELB", "ConsumedLCUs",
                        "LoadBalancerUsage", "LCUUsage"),
        "network": ("AWS/NetworkELB", "ConsumedLCUs",
                    "LoadBalancerUsage", "LCUUsage"),
    }

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        lbs = safe(
            lambda: list(ctx.paginate(
                "elbv2", "describe_load_balancers", "LoadBalancers")),
            [], "elbv2:DescribeLoadBalancers " + ctx.region,
        )
        out: list[ResourceCost] = []
        if not lbs:
            return out

        # The CloudWatch LoadBalancer dimension is the ARN suffix, e.g.
        # "app/my-lb/50dc6c495c0c9188" - not the plain name.
        dims = {}
        for lb in lbs:
            arn = lb["LoadBalancerArn"]
            dims[arn] = arn.split(":loadbalancer/", 1)[-1]

        queries = []
        for lb in lbs:
            if lb.get("Type") not in self.CONFIG:
                continue
            arn = lb["LoadBalancerArn"]
            namespace = self.CONFIG[lb["Type"]][0]
            queries.append(MetricQuery("lcu::" + arn, namespace, "ConsumedLCUs",
                                       {"LoadBalancer": dims[arn]}))
        data = ctx.metrics().read(queries) if queries else {}

        for lb in lbs:
            lb_type = lb.get("Type")
            if lb_type not in self.CONFIG:
                continue
            arn, name = lb["LoadBalancerArn"], lb["LoadBalancerName"]
            family = "Load Balancer-Application" if lb_type == "application" \
                else "Load Balancer-Network"

            hourly = ctx.pricing.price(
                "AWSELB", {"productFamily": family, "usagetype": "LoadBalancerUsage"},
                region=ctx.region, unit_hint="Hrs")
            if hourly:
                out.append(ctx.cost(
                    service="elb", resource_type=lb_type + "_load_balancer",
                    resource_id=name, usd_per_hour=hourly,
                    tier=Tier.INVENTORY, dimension="hours"))

            lcu_hr = data.get("lcu::" + arn, 0.0)
            if lcu_hr > 0:
                lcu_price = ctx.pricing.price(
                    "AWSELB", {"productFamily": family, "usagetype": "LCUUsage"},
                    region=ctx.region, unit_hint="LCU-Hrs")
                if lcu_price:
                    out.append(ctx.cost(
                        service="elb", resource_type=lb_type + "_load_balancer",
                        resource_id=name, usd_per_hour=lcu_hr * lcu_price,
                        tier=Tier.REALTIME, dimension="lcu"))
        return out


@register
class CloudFrontEstimator(Estimator):
    """CloudFront is a global service: its metrics live in us-east-1 regardless of
    where the traffic was actually served."""

    name = "cloudfront"
    tier = Tier.REALTIME
    cadence = "realtime"
    global_service = True
    required_actions = ("cloudfront:ListDistributions", "cloudwatch:GetMetricData")

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        # The distributions are nested one level down, under DistributionList.Items.
        def _list() -> list[dict]:
            client = ctx.session.client("cloudfront", "us-east-1")
            items: list[dict] = []
            for page in client.get_paginator("list_distributions").paginate():
                items.extend(page.get("DistributionList", {}).get("Items", []))
            return items

        dists = safe(_list, [], "cloudfront:ListDistributions")
        if not dists:
            return []

        cw = ctx.session.client("cloudwatch", "us-east-1")
        from ..cloudwatch import MetricReader
        reader = MetricReader(cw, window_seconds=ctx.window)

        queries = []
        for d in dists:
            did = d["Id"]
            dim = {"DistributionId": did, "Region": "Global"}
            queries.append(MetricQuery("bytes::" + did, "AWS/CloudFront",
                                       "BytesDownloaded", dim, period=300))
            queries.append(MetricQuery("req::" + did, "AWS/CloudFront",
                                       "Requests", dim, period=300))
        data = reader.read(queries)

        per_gb = priced(ctx.pricing.price(
            "AmazonCloudFront", {"productFamily": "Data Transfer"},
            unit_hint="GB"), "cloudfront.gb", "cloudfront")
        per_req = priced(ctx.pricing.price(
            "AmazonCloudFront", {"productFamily": "Request"},
            unit_hint="Requests"), "cloudfront.request", "cloudfront")

        out: list[ResourceCost] = []
        for d in dists:
            did = d["Id"]
            gb_hr = data.get("bytes::" + did, 0.0) / GB
            req_hr = data.get("req::" + did, 0.0)
            label = (d.get("Aliases", {}).get("Items") or [did])[0]
            if gb_hr > 0:
                out.append(ctx.cost(
                    service="cloudfront", resource_type="distribution",
                    resource_id=label, region="global",
                    usd_per_hour=gb_hr * per_gb,
                    tier=Tier.REALTIME, dimension="data_transfer"))
            if req_hr > 0:
                out.append(ctx.cost(
                    service="cloudfront", resource_type="distribution",
                    resource_id=label, region="global",
                    usd_per_hour=req_hr * per_req,
                    tier=Tier.REALTIME, dimension="requests"))
        return out


@register
class Route53Estimator(Estimator):
    name = "route53"
    tier = Tier.INVENTORY
    cadence = "inventory"
    global_service = True
    required_actions = ("route53:ListHostedZones",)

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        zones = safe(
            lambda: list(ctx.paginate("route53", "list_hosted_zones", "HostedZones")),
            [], "route53:ListHostedZones",
        )
        monthly = priced(
            ctx.pricing.price("AmazonRoute53", {"productFamily": "DNS Zone"},
                              unit_hint="HostedZone"),
            "route53.zone_month", "route53",
        )
        return [
            ctx.cost(service="route53", resource_type="hosted_zone",
                     resource_id=z["Name"].rstrip("."), region="global",
                     usd_per_hour=monthly / HOURS_PER_MONTH,
                     tier=Tier.INVENTORY, dimension="hosted_zone")
            for z in zones
        ]


@register
class VpcEndpointEstimator(Estimator):
    """Interface endpoints bill per AZ per hour and are easy to forget about;
    Gateway endpoints (S3, DynamoDB) are free and skipped."""

    name = "vpc_endpoint"
    tier = Tier.INVENTORY
    cadence = "inventory"
    required_actions = ("ec2:DescribeVpcEndpoints",)

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        endpoints = safe(
            lambda: list(ctx.paginate("ec2", "describe_vpc_endpoints", "VpcEndpoints")),
            [], "ec2:DescribeVpcEndpoints " + ctx.region,
        )
        rate = priced(
            ctx.pricing.price("AmazonVPC",
                              {"productFamily": "VpcEndpoint", "endpointType": "Interface"},
                              region=ctx.region, unit_hint="Hrs"),
            "vpce.az_hour", "vpc_endpoint",
        )
        out: list[ResourceCost] = []
        for ep in endpoints:
            if ep.get("VpcEndpointType") != "Interface":
                continue
            az_count = max(len(ep.get("SubnetIds") or []), 1)
            out.append(ctx.cost(
                service="vpc_endpoint", resource_type="interface_endpoint",
                resource_id=ep["VpcEndpointId"] + " " + (ep.get("ServiceName") or ""),
                usd_per_hour=rate * az_count,
                tier=Tier.INVENTORY, dimension="hours",
                tags=tags_of(ep.get("Tags"), ctx.tag_keys)))
        return out
