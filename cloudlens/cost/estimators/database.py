"""Databases: RDS, DynamoDB, ElastiCache, OpenSearch, Redshift."""
from __future__ import annotations

import logging
from typing import Iterable

from ..base import Context, Estimator, register, safe
from ..cloudwatch import MetricQuery
from ..models import ResourceCost, Tier
from ._util import GB, HOURS_PER_MONTH, priced, tags_of

log = logging.getLogger(__name__)


@register
class RdsEstimator(Estimator):
    """RDS instances: instance-hours plus allocated storage.

    Aurora clusters bill storage and I/O at the cluster level rather than per
    instance, so for Aurora only the instance-hours line is emitted here and the
    cluster-level remainder lands in the Cost Explorer fallback.
    """

    name = "rds"
    tier = Tier.INVENTORY
    cadence = "inventory"
    required_actions = ("rds:DescribeDBInstances", "rds:ListTagsForResource")

    ENGINE_MAP = {
        "aurora-mysql": "Aurora MySQL",
        "aurora-postgresql": "Aurora PostgreSQL",
        "mysql": "MySQL",
        "postgres": "PostgreSQL",
        "mariadb": "MariaDB",
        "oracle-ee": "Oracle",
        "oracle-se2": "Oracle",
        "sqlserver-ex": "SQL Server",
        "sqlserver-web": "SQL Server",
        "sqlserver-se": "SQL Server",
        "sqlserver-ee": "SQL Server",
    }

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        instances = safe(
            lambda: list(ctx.paginate("rds", "describe_db_instances", "DBInstances")),
            [], "rds:DescribeDBInstances " + ctx.region,
        )
        out: list[ResourceCost] = []
        for db in instances:
            if db.get("DBInstanceStatus") not in {"available", "backing-up", "modifying"}:
                continue
            ident = db["DBInstanceIdentifier"]
            engine = self.ENGINE_MAP.get(db["Engine"], db["Engine"])
            multi_az = db.get("MultiAZ", False)
            tags = tags_of(db.get("TagList"), ctx.tag_keys)

            rate = ctx.pricing.price(
                "AmazonRDS",
                {
                    "instanceType": db["DBInstanceClass"],
                    "databaseEngine": engine,
                    "deploymentOption": "Multi-AZ" if multi_az else "Single-AZ",
                },
                region=ctx.region, unit_hint="Hrs",
            )
            if rate is not None:
                out.append(ctx.cost(
                    service="rds", resource_type="db_instance", resource_id=ident,
                    usd_per_hour=rate, tier=Tier.INVENTORY,
                    dimension="compute", tags=tags,
                ))
            else:
                log.debug("no RDS price for %s/%s", db["DBInstanceClass"], engine)

            if not db["Engine"].startswith("aurora"):
                allocated = db.get("AllocatedStorage", 0)
                stype = {"gp2": "General Purpose", "gp3": "General Purpose",
                         "io1": "Provisioned IOPS", "io2": "Provisioned IOPS",
                         "standard": "Magnetic"}.get(db.get("StorageType", "gp2"))
                gb_month = ctx.pricing.price(
                    "AmazonRDS",
                    {"productFamily": "Database Storage", "volumeType": stype,
                     "deploymentOption": "Multi-AZ" if multi_az else "Single-AZ"},
                    region=ctx.region, unit_hint="GB-Mo",
                )
                if gb_month and allocated:
                    out.append(ctx.cost(
                        service="rds", resource_type="db_instance", resource_id=ident,
                        usd_per_hour=allocated * gb_month / HOURS_PER_MONTH,
                        tier=Tier.INVENTORY, dimension="storage", tags=tags,
                    ))
        return out


@register
class DynamoDbEstimator(Estimator):
    """DynamoDB tables.

    On-demand tables are genuinely realtime: ConsumedRead/WriteCapacityUnits are
    1-minute metrics per TableName that map straight onto RRU/WRU billing. Provisioned
    tables bill on what is reserved, so those come from DescribeTable instead.
    """

    name = "dynamodb"
    tier = Tier.REALTIME
    cadence = "realtime"
    required_actions = ("dynamodb:ListTables", "dynamodb:DescribeTable",
                        "cloudwatch:GetMetricData")

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        names = safe(
            lambda: list(ctx.paginate("dynamodb", "list_tables", "TableNames")),
            [], "dynamodb:ListTables " + ctx.region,
        )
        if not names:
            return []

        ddb = ctx.client("dynamodb")
        tables = []
        for nm in names:
            desc = safe(lambda n=nm: ddb.describe_table(TableName=n)["Table"],
                        None, "dynamodb:DescribeTable")
            if desc:
                tables.append(desc)

        on_demand = [t for t in tables
                     if (t.get("BillingModeSummary", {}).get("BillingMode")
                         == "PAY_PER_REQUEST")]
        provisioned = [t for t in tables if t not in on_demand]

        out: list[ResourceCost] = []

        if on_demand:
            rru = priced(ctx.pricing.price(
                "AmazonDynamoDB", {"group": "DDB-ReadUnits"},
                region=ctx.region, unit_hint="ReadRequestUnits"),
                "ddb.rru", "dynamodb")
            wru = priced(ctx.pricing.price(
                "AmazonDynamoDB", {"group": "DDB-WriteUnits"},
                region=ctx.region, unit_hint="WriteRequestUnits"),
                "ddb.wru", "dynamodb")
            queries = []
            for t in on_demand:
                nm = t["TableName"]
                queries.append(MetricQuery("r::" + nm, "AWS/DynamoDB",
                                           "ConsumedReadCapacityUnits", {"TableName": nm}))
                queries.append(MetricQuery("w::" + nm, "AWS/DynamoDB",
                                           "ConsumedWriteCapacityUnits", {"TableName": nm}))
            data = ctx.metrics().read(queries)
            for t in on_demand:
                nm = t["TableName"]
                reads, writes = data.get("r::" + nm, 0.0), data.get("w::" + nm, 0.0)
                if reads:
                    out.append(ctx.cost(
                        service="dynamodb", resource_type="table", resource_id=nm,
                        usd_per_hour=reads * rru, tier=Tier.REALTIME, dimension="reads"))
                if writes:
                    out.append(ctx.cost(
                        service="dynamodb", resource_type="table", resource_id=nm,
                        usd_per_hour=writes * wru, tier=Tier.REALTIME, dimension="writes"))

        for t in provisioned:
            nm = t["TableName"]
            tp = t.get("ProvisionedThroughput", {})
            rcu, wcu = tp.get("ReadCapacityUnits", 0), tp.get("WriteCapacityUnits", 0)
            rcu_hr = ctx.pricing.price(
                "AmazonDynamoDB", {"group": "DDB-ReadUnits"},
                region=ctx.region, unit_hint="ReadCapacityUnit-Hrs")
            wcu_hr = ctx.pricing.price(
                "AmazonDynamoDB", {"group": "DDB-WriteUnits"},
                region=ctx.region, unit_hint="WriteCapacityUnit-Hrs")
            if rcu and rcu_hr:
                out.append(ctx.cost(
                    service="dynamodb", resource_type="table", resource_id=nm,
                    usd_per_hour=rcu * rcu_hr, tier=Tier.INVENTORY, dimension="reads"))
            if wcu and wcu_hr:
                out.append(ctx.cost(
                    service="dynamodb", resource_type="table", resource_id=nm,
                    usd_per_hour=wcu * wcu_hr, tier=Tier.INVENTORY, dimension="writes"))

        # Storage. TableSizeBytes refreshes roughly every 6 hours, which is fine for a
        # figure that moves slowly anyway.
        gb_month = priced(ctx.pricing.price(
            "AmazonDynamoDB", {"productFamily": "Database Storage"},
            region=ctx.region, unit_hint="GB-Mo"), "ddb.storage_gb_month", "dynamodb")
        for t in tables:
            size_gb = t.get("TableSizeBytes", 0) / GB
            if size_gb > 0:
                out.append(ctx.cost(
                    service="dynamodb", resource_type="table",
                    resource_id=t["TableName"],
                    usd_per_hour=size_gb * gb_month / HOURS_PER_MONTH,
                    tier=Tier.INVENTORY, dimension="storage"))
        return out


@register
class ElastiCacheEstimator(Estimator):
    name = "elasticache"
    tier = Tier.INVENTORY
    cadence = "inventory"
    required_actions = ("elasticache:DescribeCacheClusters",)

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        clusters = safe(
            lambda: list(ctx.paginate(
                "elasticache", "describe_cache_clusters", "CacheClusters")),
            [], "elasticache:DescribeCacheClusters " + ctx.region,
        )
        out: list[ResourceCost] = []
        for c in clusters:
            node_type = c.get("CacheNodeType")
            count = c.get("NumCacheNodes", 1)
            engine = "Redis" if "redis" in (c.get("Engine") or "").lower() else "Memcached"
            rate = ctx.pricing.price(
                "AmazonElastiCache",
                {"instanceType": node_type, "cacheEngine": engine},
                region=ctx.region, unit_hint="Hrs",
            )
            if rate is None:
                continue
            out.append(ctx.cost(
                service="elasticache", resource_type="cluster",
                resource_id=c["CacheClusterId"], usd_per_hour=rate * count,
                tier=Tier.INVENTORY, dimension="compute"))
        return out


@register
class OpenSearchEstimator(Estimator):
    name = "opensearch"
    tier = Tier.INVENTORY
    cadence = "inventory"
    required_actions = ("es:ListDomainNames", "es:DescribeDomains")

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        client = ctx.client("opensearch")
        names = safe(
            lambda: [d["DomainName"]
                     for d in client.list_domain_names().get("DomainNames", [])],
            [], "opensearch:ListDomainNames " + ctx.region,
        )
        if not names:
            return []
        domains = safe(
            lambda: client.describe_domains(DomainNames=names).get("DomainStatusList", []),
            [], "opensearch:DescribeDomains",
        )
        out: list[ResourceCost] = []
        for d in domains:
            cfg = d.get("ClusterConfig", {})
            itype, count = cfg.get("InstanceType"), cfg.get("InstanceCount", 1)
            rate = ctx.pricing.price(
                "AmazonES", {"instanceType": itype},
                region=ctx.region, unit_hint="Hrs")
            if rate:
                out.append(ctx.cost(
                    service="opensearch", resource_type="domain",
                    resource_id=d["DomainName"], usd_per_hour=rate * count,
                    tier=Tier.INVENTORY, dimension="compute"))

            ebs = d.get("EBSOptions", {})
            if ebs.get("EBSEnabled"):
                size = ebs.get("VolumeSize", 0) * count
                gb_month = ctx.pricing.price(
                    "AmazonES",
                    {"productFamily": "Elastic Search Volume",
                     "storageMedia": "SSD-backed"},
                    region=ctx.region, unit_hint="GB-Mo")
                if gb_month and size:
                    out.append(ctx.cost(
                        service="opensearch", resource_type="domain",
                        resource_id=d["DomainName"],
                        usd_per_hour=size * gb_month / HOURS_PER_MONTH,
                        tier=Tier.INVENTORY, dimension="storage"))
        return out


@register
class RedshiftEstimator(Estimator):
    name = "redshift"
    tier = Tier.INVENTORY
    cadence = "inventory"
    required_actions = ("redshift:DescribeClusters",)

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        clusters = safe(
            lambda: list(ctx.paginate("redshift", "describe_clusters", "Clusters")),
            [], "redshift:DescribeClusters " + ctx.region,
        )
        out: list[ResourceCost] = []
        for c in clusters:
            if c.get("ClusterStatus") != "available":
                continue
            rate = ctx.pricing.price(
                "AmazonRedshift", {"instanceType": c.get("NodeType")},
                region=ctx.region, unit_hint="Hrs")
            if rate:
                out.append(ctx.cost(
                    service="redshift", resource_type="cluster",
                    resource_id=c["ClusterIdentifier"],
                    usd_per_hour=rate * c.get("NumberOfNodes", 1),
                    tier=Tier.INVENTORY, dimension="compute",
                    tags=tags_of(c.get("Tags"), ctx.tag_keys)))
        return out
