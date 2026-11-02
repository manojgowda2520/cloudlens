"""Compute: Lambda, EC2, EBS, Fargate, EKS."""
from __future__ import annotations

import logging
from typing import Iterable

from ..base import Context, Estimator, register, safe
from ..cloudwatch import MetricQuery
from ..models import ResourceCost, Tier
from ._util import HOURS_PER_MONTH, priced, tags_of

log = logging.getLogger(__name__)


@register
class LambdaEstimator(Estimator):
    """Per-function cost from Invocations + Duration.

    This is the flagship case: Lambda publishes both billing dimensions as 1-minute
    CloudWatch metrics keyed on FunctionName, so the derived figure tracks the real
    bill to within rounding on billed duration.

    Not modelled: provisioned concurrency (billed even at zero invocations) and
    ephemeral storage above the included 512 MB.
    """

    name = "lambda"
    tier = Tier.REALTIME
    cadence = "realtime"
    required_actions = ("lambda:ListFunctions", "lambda:ListTags", "cloudwatch:GetMetricData")

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        functions = safe(
            lambda: list(ctx.paginate("lambda", "list_functions", "Functions")),
            [], "lambda:ListFunctions " + ctx.region,
        )
        if not functions:
            return []

        queries: list[MetricQuery] = []
        for fn in functions:
            nm = fn["FunctionName"]
            queries.append(MetricQuery("inv::" + nm, "AWS/Lambda", "Invocations",
                                       {"FunctionName": nm}))
            queries.append(MetricQuery("dur::" + nm, "AWS/Lambda", "Duration",
                                       {"FunctionName": nm}))
        data = ctx.metrics().read(queries)

        # One price lookup per architecture, not one per function.
        rates: dict[str, tuple[float, float]] = {}
        for arch in {(f.get("Architectures") or ["x86_64"])[0] for f in functions}:
            arm = arch == "arm64"
            suffix = "-ARM" if arm else ""
            req = ctx.pricing.price(
                "AWSLambda", {"group": "AWS-Lambda-Requests" + suffix},
                region=ctx.region, unit_hint="Request",
            )
            dur = ctx.pricing.price(
                "AWSLambda", {"group": "AWS-Lambda-Duration" + suffix},
                region=ctx.region, unit_hint="Second",
            )
            rates[arch] = (
                priced(req, "lambda.request", "lambda"),
                priced(dur, "lambda.gb_second_arm" if arm else "lambda.gb_second", "lambda"),
            )

        out: list[ResourceCost] = []
        for fn in functions:
            nm = fn["FunctionName"]
            inv_hr = data.get("inv::" + nm, 0.0)
            dur_ms_hr = data.get("dur::" + nm, 0.0)
            if inv_hr <= 0 and dur_ms_hr <= 0:
                continue

            arch = (fn.get("Architectures") or ["x86_64"])[0]
            req_price, gbs_price = rates[arch]
            mem_gb = fn.get("MemorySize", 128) / 1024.0
            gb_seconds_hr = (dur_ms_hr / 1000.0) * mem_gb

            tags = {}
            if ctx.tag_keys:
                raw = safe(
                    lambda arn=fn["FunctionArn"]:
                        ctx.client("lambda").list_tags(Resource=arn).get("Tags", {}),
                    {}, "lambda:ListTags",
                )
                tags = tags_of(raw, ctx.tag_keys)

            common = dict(service="lambda", resource_type="function", resource_id=nm,
                          tier=Tier.REALTIME, tags=tags)
            if inv_hr > 0:
                out.append(ctx.cost(usd_per_hour=inv_hr * req_price,
                                    dimension="requests", **common))
            if gb_seconds_hr > 0:
                out.append(ctx.cost(usd_per_hour=gb_seconds_hr * gbs_price,
                                    dimension="duration", **common))
        return out


@register
class Ec2Estimator(Estimator):
    """Running instances at published on-demand rates.

    An instance costs money purely by existing, so the describe call *is* the
    measurement - no CloudWatch needed. RIs and Savings Plans are invisible at this
    layer; reconcile.py measures the resulting gap against Cost Explorer.
    """

    name = "ec2"
    tier = Tier.INVENTORY
    cadence = "inventory"
    required_actions = ("ec2:DescribeInstances",)

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        reservations = safe(
            lambda: list(ctx.paginate(
                "ec2", "describe_instances", "Reservations",
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}],
            )),
            [], "ec2:DescribeInstances " + ctx.region,
        )
        out: list[ResourceCost] = []
        for res in reservations:
            for inst in res.get("Instances", []):
                itype = inst["InstanceType"]
                os_name = _ec2_os(inst)
                tenancy = inst.get("Placement", {}).get("Tenancy") or "default"
                rate = ctx.pricing.price(
                    "AmazonEC2",
                    {
                        "instanceType": itype,
                        "operatingSystem": os_name,
                        "tenancy": "Shared" if tenancy == "default" else "Dedicated",
                        "preInstalledSw": "NA",
                        "capacitystatus": "Used",
                        "licenseModel": "No License required",
                    },
                    region=ctx.region, unit_hint="Hrs",
                )
                if rate is None:
                    log.debug("no EC2 price for %s/%s in %s", itype, os_name, ctx.region)
                    continue
                out.append(ctx.cost(
                    service="ec2", resource_type="instance",
                    resource_id=inst["InstanceId"], usd_per_hour=rate,
                    tier=Tier.INVENTORY, dimension="compute",
                    tags=tags_of(inst.get("Tags"), ctx.tag_keys),
                ))
        return out


def _ec2_os(inst: dict) -> str:
    details = (inst.get("PlatformDetails") or "").lower()
    if "windows" in details:
        return "Windows"
    if "red hat" in details or "rhel" in details:
        return "RHEL"
    if "suse" in details:
        return "SUSE"
    return "Linux"


@register
class EbsEstimator(Estimator):
    """EBS volumes: provisioned capacity, plus provisioned IOPS and throughput above
    the baseline included with gp3."""

    name = "ebs"
    tier = Tier.INVENTORY
    cadence = "inventory"
    required_actions = ("ec2:DescribeVolumes",)

    GP3_FREE_IOPS = 3000
    GP3_FREE_THROUGHPUT = 125   # MB/s

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        volumes = safe(
            lambda: list(ctx.paginate("ec2", "describe_volumes", "Volumes")),
            [], "ec2:DescribeVolumes " + ctx.region,
        )
        out: list[ResourceCost] = []
        for vol in volumes:
            vtype, size, vid = vol["VolumeType"], vol["Size"], vol["VolumeId"]
            tags = tags_of(vol.get("Tags"), ctx.tag_keys)

            gb_month = ctx.pricing.price(
                "AmazonEC2", {"productFamily": "Storage", "volumeApiName": vtype},
                region=ctx.region, unit_hint="GB-Mo",
            )
            if gb_month is not None:
                out.append(ctx.cost(
                    service="ebs", resource_type="volume", resource_id=vid,
                    usd_per_hour=size * gb_month / HOURS_PER_MONTH,
                    tier=Tier.INVENTORY, dimension="storage", tags=tags,
                ))

            iops = vol.get("Iops", 0)
            billable_iops = iops - self.GP3_FREE_IOPS if vtype == "gp3" else iops
            if vtype in {"gp3", "io1", "io2"} and billable_iops > 0:
                iops_month = ctx.pricing.price(
                    "AmazonEC2",
                    {"productFamily": "System Operation", "volumeApiName": vtype},
                    region=ctx.region, unit_hint="IOPS-Mo",
                )
                if iops_month:
                    out.append(ctx.cost(
                        service="ebs", resource_type="volume", resource_id=vid,
                        usd_per_hour=billable_iops * iops_month / HOURS_PER_MONTH,
                        tier=Tier.INVENTORY, dimension="iops", tags=tags,
                    ))

            tput = vol.get("Throughput", 0)
            if vtype == "gp3" and tput > self.GP3_FREE_THROUGHPUT:
                tput_month = ctx.pricing.price(
                    "AmazonEC2",
                    {"productFamily": "Provisioned Throughput", "volumeApiName": vtype},
                    region=ctx.region, unit_hint="MiBps-Mo",
                )
                if tput_month:
                    out.append(ctx.cost(
                        service="ebs", resource_type="volume", resource_id=vid,
                        usd_per_hour=(tput - self.GP3_FREE_THROUGHPUT)
                        * tput_month / HOURS_PER_MONTH,
                        tier=Tier.INVENTORY, dimension="throughput", tags=tags,
                    ))
        return out


@register
class FargateEstimator(Estimator):
    """ECS Fargate tasks, priced on the vCPU and GB the running task reserves."""

    name = "fargate"
    tier = Tier.INVENTORY
    cadence = "inventory"
    required_actions = ("ecs:ListClusters", "ecs:ListTasks", "ecs:DescribeTasks")

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        clusters = safe(
            lambda: list(ctx.paginate("ecs", "list_clusters", "clusterArns")),
            [], "ecs:ListClusters " + ctx.region,
        )
        if not clusters:
            return []

        vcpu_hr = ctx.pricing.price(
            "AmazonECS", {"cputype": "perCPU", "tenancy": "Shared"},
            region=ctx.region, unit_hint="hours",
        )
        gb_hr = ctx.pricing.price(
            "AmazonECS", {"memorytype": "perGB", "tenancy": "Shared"},
            region=ctx.region, unit_hint="hours",
        )
        if vcpu_hr is None or gb_hr is None:
            log.debug("no Fargate price in %s", ctx.region)
            return []

        ecs = ctx.client("ecs")
        out: list[ResourceCost] = []
        for cluster in clusters:
            arns = safe(
                lambda c=cluster: list(ctx.paginate(
                    "ecs", "list_tasks", "taskArns", cluster=c, desiredStatus="RUNNING",
                )),
                [], "ecs:ListTasks",
            )
            for i in range(0, len(arns), 100):
                chunk = arns[i : i + 100]
                tasks = safe(
                    lambda c=cluster, ch=chunk: ecs.describe_tasks(
                        cluster=c, tasks=ch, include=["TAGS"]).get("tasks", []),
                    [], "ecs:DescribeTasks",
                )
                for task in tasks:
                    if task.get("launchType") != "FARGATE":
                        continue
                    cpu = float(task.get("cpu") or 0) / 1024.0      # CPU units -> vCPU
                    mem = float(task.get("memory") or 0) / 1024.0   # MiB -> GB
                    if cpu <= 0 and mem <= 0:
                        continue
                    cluster_name = cluster.rsplit("/", 1)[-1]
                    task_id = task["taskArn"].rsplit("/", 1)[-1]
                    out.append(ctx.cost(
                        service="fargate", resource_type="task",
                        resource_id=cluster_name + "/" + task_id,
                        usd_per_hour=cpu * vcpu_hr + mem * gb_hr,
                        tier=Tier.INVENTORY, dimension="compute",
                        tags=tags_of(task.get("tags"), ctx.tag_keys),
                    ))
        return out


@register
class EksEstimator(Estimator):
    """The EKS control-plane hourly charge. Worker nodes appear under ec2/fargate."""

    name = "eks"
    tier = Tier.INVENTORY
    cadence = "inventory"
    required_actions = ("eks:ListClusters",)

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        names = safe(
            lambda: list(ctx.paginate("eks", "list_clusters", "clusters")),
            [], "eks:ListClusters " + ctx.region,
        )
        if not names:
            return []
        rate = priced(
            ctx.pricing.price("AmazonEKS", {"usagetype": "AmazonEKS-Hours:perCluster"},
                              region=ctx.region, unit_hint="hours"),
            "eks.cluster_hour", "eks",
        )
        return [
            ctx.cost(service="eks", resource_type="cluster", resource_id=n,
                     usd_per_hour=rate, tier=Tier.INVENTORY, dimension="control_plane")
            for n in names
        ]
