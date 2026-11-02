"""Storage: S3, EFS, ECR."""
from __future__ import annotations

import logging
from typing import Iterable

from ..base import Context, Estimator, register, safe
from ..cloudwatch import MetricQuery
from ..models import ResourceCost, Tier
from ._util import GB, HOURS_PER_MONTH, priced, tags_of

log = logging.getLogger(__name__)


@register
class S3Estimator(Estimator):
    """Per-bucket storage cost, split by storage class.

    S3 publishes BucketSizeBytes as a *daily* metric, so this is the one place where
    "realtime" is not on the table for storage - the figure moves once a day. Request
    charges (GET/PUT) need per-bucket request metrics enabled, which is itself a paid
    feature and off by default; when they are absent the request line is simply not
    emitted and those dollars land in the Cost Explorer fallback instead.
    """

    name = "s3"
    tier = Tier.INVENTORY
    cadence = "inventory"
    required_actions = ("s3:ListAllMyBuckets", "s3:GetBucketLocation",
                        "cloudwatch:GetMetricData")

    # CloudWatch StorageType dimension -> Pricing API volumeType.
    STORAGE_CLASSES = {
        "StandardStorage": "Standard",
        "StandardIAStorage": "Standard - Infrequent Access",
        "OneZoneIAStorage": "One Zone - Infrequent Access",
        "IntelligentTieringFAStorage": "Intelligent-Tiering Frequent Access",
        "IntelligentTieringIAStorage": "Intelligent-Tiering Infrequent Access",
        "IntelligentTieringAAStorage": "Intelligent-Tiering Archive Access",
        "GlacierInstantRetrievalStorage": "Glacier Instant Retrieval",
        "GlacierStorage": "Amazon Glacier Flexible Retrieval",
        "DeepArchiveStorage": "Glacier Deep Archive",
    }

    # Two days of daily datapoints - enough to survive a metric that has not landed yet.
    WINDOW = 172800
    PERIOD = 86400

    def __init__(self) -> None:
        self._locations: dict[str, dict[str, str]] = {}   # account -> bucket -> region

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        buckets = self._buckets_in_region(ctx)
        if not buckets:
            return []

        queries = [
            MetricQuery(
                key=cls + "::" + b,
                namespace="AWS/S3",
                metric_name="BucketSizeBytes",
                dimensions={"BucketName": b, "StorageType": cls},
                stat="Average",
                period=self.PERIOD,
            )
            for b in buckets
            for cls in self.STORAGE_CLASSES
        ]
        data = ctx.metrics(window=self.WINDOW).read(queries)

        out: list[ResourceCost] = []
        for key, size_bytes in data.items():
            cls, bucket = key.split("::", 1)
            size_gb = size_bytes / GB
            if size_gb <= 0:
                continue
            gb_month = ctx.pricing.price(
                "AmazonS3",
                {"productFamily": "Storage", "volumeType": self.STORAGE_CLASSES[cls]},
                region=ctx.region, unit_hint="GB-Mo",
            )
            gb_month = priced(gb_month, "s3.standard_gb_month", "s3")
            out.append(ctx.cost(
                service="s3", resource_type="bucket", resource_id=bucket,
                usd_per_hour=size_gb * gb_month / HOURS_PER_MONTH,
                tier=Tier.INVENTORY,
                dimension="storage_" + cls.replace("Storage", "").lower(),
            ))
        return out

    def _buckets_in_region(self, ctx: Context) -> list[str]:
        """ListBuckets is global; each bucket's metrics live in its own region."""
        acct = ctx.account_id
        if acct not in self._locations:
            s3 = ctx.session.client("s3", "us-east-1")
            names = safe(lambda: [b["Name"] for b in s3.list_buckets().get("Buckets", [])],
                         [], "s3:ListAllMyBuckets")
            mapping = {}
            for name in names:
                loc = safe(
                    lambda n=name: s3.get_bucket_location(Bucket=n).get("LocationConstraint"),
                    None, "s3:GetBucketLocation",
                )
                # The API returns None for us-east-1 and "EU" for the legacy eu-west-1.
                mapping[name] = {None: "us-east-1", "EU": "eu-west-1"}.get(loc, loc)
            self._locations[acct] = mapping
        return [b for b, r in self._locations[acct].items() if r == ctx.region]


@register
class EfsEstimator(Estimator):
    name = "efs"
    tier = Tier.INVENTORY
    cadence = "inventory"
    required_actions = ("elasticfilesystem:DescribeFileSystems",)

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        systems = safe(
            lambda: list(ctx.paginate("efs", "describe_file_systems", "FileSystems")),
            [], "efs:DescribeFileSystems " + ctx.region,
        )
        out: list[ResourceCost] = []
        for fs in systems:
            size = fs.get("SizeInBytes", {})
            fsid = fs["FileSystemId"]
            tags = tags_of(fs.get("Tags"), ctx.tag_keys)
            one_zone = fs.get("AvailabilityZoneName") is not None

            for field, cls_name, label in (
                ("ValueInStandard", "General Purpose", "standard"),
                ("ValueInIA", "Infrequent Access", "infrequent_access"),
                ("ValueInArchive", "Archive", "archive"),
            ):
                gb = size.get(field, 0) / GB
                if gb <= 0:
                    continue
                gb_month = ctx.pricing.price(
                    "AmazonEFS",
                    {"productFamily": "Storage", "storageClass": cls_name,
                     "storageType": "One Zone" if one_zone else "Regional"},
                    region=ctx.region, unit_hint="GB-Mo",
                )
                gb_month = priced(gb_month, "efs.gb_month", "efs")
                out.append(ctx.cost(
                    service="efs", resource_type="filesystem", resource_id=fsid,
                    usd_per_hour=gb * gb_month / HOURS_PER_MONTH,
                    tier=Tier.INVENTORY, dimension="storage_" + label, tags=tags,
                ))
        return out


@register
class EcrEstimator(Estimator):
    """ECR repositories, priced on the sum of image sizes.

    Layers shared between images are stored once but counted once per image here, so
    this over-estimates on repos with many tags of the same build. It is still the
    only per-repository signal available - ECR publishes no size metric.
    """

    name = "ecr"
    tier = Tier.INVENTORY
    cadence = "inventory"
    required_actions = ("ecr:DescribeRepositories", "ecr:DescribeImages")

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        repos = safe(
            lambda: list(ctx.paginate("ecr", "describe_repositories", "repositories")),
            [], "ecr:DescribeRepositories " + ctx.region,
        )
        if not repos:
            return []
        gb_month = priced(
            ctx.pricing.price("AmazonECR", {"productFamily": "EC2 Container Registry"},
                              region=ctx.region, unit_hint="GB-Mo"),
            "ecr.gb_month", "ecr",
        )
        out: list[ResourceCost] = []
        for repo in repos:
            name = repo["repositoryName"]
            images = safe(
                lambda n=name: list(ctx.paginate(
                    "ecr", "describe_images", "imageDetails", repositoryName=n)),
                [], "ecr:DescribeImages",
            )
            total_gb = sum(i.get("imageSizeInBytes", 0) for i in images) / GB
            if total_gb <= 0:
                continue
            out.append(ctx.cost(
                service="ecr", resource_type="repository", resource_id=name,
                usd_per_hour=total_gb * gb_month / HOURS_PER_MONTH,
                tier=Tier.INVENTORY, dimension="storage",
            ))
        return out
