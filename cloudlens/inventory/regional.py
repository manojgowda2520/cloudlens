"""Regional collectors. Each runs once per (account, enabled region)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Iterator

from .. import secrets
from .base import Ctx, Resource, collector, tags_of

_DAY = 86400


def _json(value):
    if isinstance(value, str) and value:
        try:
            return json.loads(value)
        except ValueError:
            return None
    return value or None


# --------------------------------------------------------------------- compute

@collector("lambda")
def lambda_(ctx: Ctx) -> Iterator[Resource]:
    lam = ctx.client("lambda")
    functions = ctx.pages(lam, "list_functions", "Functions")
    if not functions:
        return
    invocations = _lambda_invocations(ctx, [f["FunctionName"] for f in functions])
    urls_q = ("ResourceNotFoundException",)
    for f in functions:
        name = f["FunctionName"]
        env = (f.get("Environment") or {}).get("Variables")
        if env:
            f["Environment"]["Variables"], f["SecretHits"] = secrets.scrub_env(env)
        f["Policy"] = _json(ctx.call(lambda: lam.get_policy(FunctionName=name)["Policy"],
                                     "lambda:GetPolicy", None, urls_q))
        f["UrlConfigs"] = ctx.call(lambda: lam.list_function_url_configs(FunctionName=name)["FunctionUrlConfigs"],
                                   "lambda:ListFunctionUrlConfigs", [], urls_q)
        f["Invocations90d"] = invocations.get(name)
        tags = ctx.call(lambda: lam.list_tags(Resource=f["FunctionArn"])["Tags"], "lambda:ListTags", {}, urls_q)
        yield ctx.res("lambda", "function", f["FunctionArn"], name, f, tags=tags_of(tags),
                      created=f.get("LastModified"))


def _lambda_invocations(ctx: Ctx, names: list[str]) -> dict:
    """Total invocations per function over 90 days, one GetMetricData batch per 500."""
    cw = ctx.client("cloudwatch")
    end = datetime.now(timezone.utc)
    out: dict[str, float] = {}
    for i in range(0, len(names), 500):
        chunk = names[i:i + 500]
        queries = [{
            "Id": f"m{j}",
            "MetricStat": {"Metric": {"Namespace": "AWS/Lambda", "MetricName": "Invocations",
                                      "Dimensions": [{"Name": "FunctionName", "Value": n}]},
                           "Period": 90 * _DAY, "Stat": "Sum"},
        } for j, n in enumerate(chunk)]
        def run():
            res = {}
            for page in cw.get_paginator("get_metric_data").paginate(
                    MetricDataQueries=queries, StartTime=end - timedelta(days=90), EndTime=end):
                for r in page["MetricDataResults"]:
                    res[r["Id"]] = res.get(r["Id"], 0.0) + sum(r.get("Values") or [])
            return res
        sums = ctx.call(run, "cloudwatch:GetMetricData", None)
        if sums is None:
            continue   # unknown, not zero - checks must not call these idle
        for j, n in enumerate(chunk):
            out[n] = sums.get(f"m{j}", 0.0)
    return out


@collector("ec2")
def ec2(ctx: Ctx) -> Iterator[Resource]:
    c = ctx.client("ec2")
    for res in ctx.pages(c, "describe_instances", "Reservations"):
        for i in res.get("Instances") or []:
            if (i.get("State") or {}).get("Name") == "terminated":
                continue
            name = tags_of(i.get("Tags")).get("Name", i["InstanceId"])
            yield ctx.res("ec2", "instance", ctx.arn("ec2", f"instance/{i['InstanceId']}"), name, i,
                          created=i.get("LaunchTime"))

    for v in ctx.pages(c, "describe_volumes", "Volumes"):
        yield ctx.res("ec2", "volume", ctx.arn("ec2", f"volume/{v['VolumeId']}"),
                      tags_of(v.get("Tags")).get("Name", v["VolumeId"]), v, created=v.get("CreateTime"))

    public = {s["SnapshotId"] for s in ctx.pages(c, "describe_snapshots", "Snapshots",
                                                 OwnerIds=["self"], RestorableByUserIds=["all"])}
    for s in ctx.pages(c, "describe_snapshots", "Snapshots", OwnerIds=["self"]):
        s["Public"] = s["SnapshotId"] in public
        yield ctx.res("ec2", "snapshot", ctx.arn("ec2", f"snapshot/{s['SnapshotId']}"),
                      tags_of(s.get("Tags")).get("Name", s["SnapshotId"]), s, created=s.get("StartTime"))

    for img in ctx.call(lambda: c.describe_images(Owners=["self"])["Images"], "ec2:DescribeImages", []):
        yield ctx.res("ec2", "image", ctx.arn("ec2", f"image/{img['ImageId']}"),
                      img.get("Name") or img["ImageId"], img, created=img.get("CreationDate"))

    for a in ctx.call(lambda: c.describe_addresses()["Addresses"], "ec2:DescribeAddresses", []):
        key = a.get("AllocationId") or a.get("PublicIp")
        yield ctx.res("ec2", "elastic-ip", ctx.arn("ec2", f"elastic-ip/{key}"), a.get("PublicIp", key), a)

    for n in ctx.pages(c, "describe_nat_gateways", "NatGateways"):
        if n.get("State") in ("deleted", "failed"):
            continue
        yield ctx.res("ec2", "nat-gateway", ctx.arn("ec2", f"natgateway/{n['NatGatewayId']}"),
                      tags_of(n.get("Tags")).get("Name", n["NatGatewayId"]), n, created=n.get("CreateTime"))


@collector("network")
def network(ctx: Ctx) -> Iterator[Resource]:
    c = ctx.client("ec2")
    in_use = set()
    for eni in ctx.pages(c, "describe_network_interfaces", "NetworkInterfaces"):
        in_use.update(g["GroupId"] for g in eni.get("Groups") or [])
    for g in ctx.pages(c, "describe_security_groups", "SecurityGroups"):
        g["InUse"] = g["GroupId"] in in_use
        yield ctx.res("ec2", "security-group", ctx.arn("ec2", f"security-group/{g['GroupId']}"),
                      f"{g['GroupName']} ({g['GroupId']})", g)

    flow = {f.get("ResourceId") for f in ctx.pages(c, "describe_flow_logs", "FlowLogs")}
    for v in ctx.pages(c, "describe_vpcs", "Vpcs"):
        v["FlowLogs"] = v["VpcId"] in flow
        yield ctx.res("ec2", "vpc", ctx.arn("ec2", f"vpc/{v['VpcId']}"),
                      tags_of(v.get("Tags")).get("Name", v["VpcId"]), v)

    for e in ctx.pages(c, "describe_vpc_endpoints", "VpcEndpoints"):
        yield ctx.res("ec2", "vpc-endpoint", ctx.arn("ec2", f"vpc-endpoint/{e['VpcEndpointId']}"),
                      e.get("ServiceName", e["VpcEndpointId"]), e, created=e.get("CreationTimestamp"))

    elb = ctx.client("elbv2")
    for lb in ctx.pages(elb, "describe_load_balancers", "LoadBalancers"):
        arn = lb["LoadBalancerArn"]
        lb["Listeners"] = ctx.pages(elb, "describe_listeners", "Listeners", LoadBalancerArn=arn)
        tgs = ctx.pages(elb, "describe_target_groups", "TargetGroups", LoadBalancerArn=arn)
        lb["TargetCount"] = sum(
            len(ctx.call(lambda: elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
                         ["TargetHealthDescriptions"], "elbv2:DescribeTargetHealth", []))
            for tg in tgs[:20])
        lb["TargetGroupCount"] = len(tgs)
        yield ctx.res("elbv2", lb.get("Type", "load-balancer"), arn, lb["LoadBalancerName"], lb,
                      tags={}, created=lb.get("CreatedTime"))

    for lb in ctx.pages(ctx.client("elb"), "describe_load_balancers", "LoadBalancerDescriptions"):
        yield ctx.res("elb", "classic", ctx.arn("elasticloadbalancing", f"loadbalancer/{lb['LoadBalancerName']}"),
                      lb["LoadBalancerName"], lb, tags={}, created=lb.get("CreatedTime"))


@collector("autoscaling")
def autoscaling(ctx: Ctx) -> Iterator[Resource]:
    for g in ctx.pages(ctx.client("autoscaling"), "describe_auto_scaling_groups", "AutoScalingGroups"):
        yield ctx.res("autoscaling", "group", g["AutoScalingGroupARN"], g["AutoScalingGroupName"], g,
                      created=g.get("CreatedTime"))


@collector("containers")
def containers(ctx: Ctx) -> Iterator[Resource]:
    ecs = ctx.client("ecs")
    arns = ctx.pages(ecs, "list_clusters", "clusterArns")
    for i in range(0, len(arns), 100):
        for cl in ctx.call(lambda: ecs.describe_clusters(clusters=arns[i:i + 100])["clusters"],
                           "ecs:DescribeClusters", []):
            yield ctx.res("ecs", "cluster", cl["clusterArn"], cl["clusterName"], cl)
    for family in ctx.pages(ecs, "list_task_definition_families", "families", status="ACTIVE")[:300]:
        td = ctx.call(lambda: ecs.describe_task_definition(taskDefinition=family)["taskDefinition"],
                      "ecs:DescribeTaskDefinition", None)
        if not td:
            continue
        hits = []
        for cdef in td.get("containerDefinitions") or []:
            env = {e["name"]: e.get("value", "") for e in cdef.get("environment") or []}
            redacted, found = secrets.scrub_env(env)
            cdef["environment"] = [{"name": k, "value": v} for k, v in redacted.items()]
            hits += [{**h, "container": cdef.get("name")} for h in found]
        td["SecretHits"] = hits
        yield ctx.res("ecs", "task-definition", td["taskDefinitionArn"], f"{family}:{td.get('revision')}",
                      td, tags={}, created=td.get("registeredAt"))

    eks = ctx.client("eks")
    for name in ctx.pages(eks, "list_clusters", "clusters"):
        cl = ctx.call(lambda: eks.describe_cluster(name=name)["cluster"], "eks:DescribeCluster", None)
        if cl:
            yield ctx.res("eks", "cluster", cl["arn"], name, cl, tags=cl.get("tags") or {},
                          created=cl.get("createdAt"))

    ecr = ctx.client("ecr")
    for r in ctx.pages(ecr, "describe_repositories", "repositories"):
        r["Policy"] = _json(ctx.call(
            lambda: ecr.get_repository_policy(repositoryName=r["repositoryName"])["policyText"],
            "ecr:GetRepositoryPolicy", None, ("RepositoryPolicyNotFoundException",)))
        yield ctx.res("ecr", "repository", r["repositoryArn"], r["repositoryName"], r, tags={},
                      created=r.get("createdAt"))

    for env in ctx.pages(ctx.client("elasticbeanstalk"), "describe_environments", "Environments"):
        if env.get("Status") == "Terminated":
            continue
        yield ctx.res("elasticbeanstalk", "environment", env["EnvironmentArn"], env["EnvironmentName"],
                      env, tags={}, created=env.get("DateCreated"))


# ------------------------------------------------------------------------ data

@collector("databases")
def databases(ctx: Ctx) -> Iterator[Resource]:
    rds = ctx.client("rds")
    for db in ctx.pages(rds, "describe_db_instances", "DBInstances"):
        yield ctx.res("rds", "instance", db["DBInstanceArn"], db["DBInstanceIdentifier"], db,
                      created=db.get("InstanceCreateTime"))
    for cl in ctx.pages(rds, "describe_db_clusters", "DBClusters"):
        yield ctx.res("rds", "cluster", cl["DBClusterArn"], cl["DBClusterIdentifier"], cl,
                      created=cl.get("ClusterCreateTime"))
    for snap in ctx.pages(rds, "describe_db_snapshots", "DBSnapshots", SnapshotType="manual")[:200]:
        attrs = ctx.call(lambda: rds.describe_db_snapshot_attributes(
            DBSnapshotIdentifier=snap["DBSnapshotIdentifier"])["DBSnapshotAttributesResult"],
            "rds:DescribeDBSnapshotAttributes", {})
        restore = next((a.get("AttributeValues") or [] for a in attrs.get("DBSnapshotAttributes") or []
                        if a.get("AttributeName") == "restore"), [])
        snap["Public"] = "all" in restore
        snap["SharedWith"] = [a for a in restore if a != "all"]
        yield ctx.res("rds", "snapshot", snap["DBSnapshotArn"], snap["DBSnapshotIdentifier"], snap,
                      created=snap.get("SnapshotCreateTime"))

    ddb = ctx.client("dynamodb")
    for name in ctx.pages(ddb, "list_tables", "TableNames")[:500]:
        t = ctx.call(lambda: ddb.describe_table(TableName=name)["Table"], "dynamodb:DescribeTable", None)
        if t:
            yield ctx.res("dynamodb", "table", t["TableArn"], name, t, tags={},
                          created=t.get("CreationDateTime"))

    ec = ctx.client("elasticache")
    for rg in ctx.pages(ec, "describe_replication_groups", "ReplicationGroups"):
        yield ctx.res("elasticache", "replication-group", rg["ARN"], rg["ReplicationGroupId"], rg, tags={},
                      created=rg.get("ReplicationGroupCreateTime"))
    for cc in ctx.pages(ec, "describe_cache_clusters", "CacheClusters"):
        if not cc.get("ReplicationGroupId"):
            yield ctx.res("elasticache", "cluster", cc["ARN"], cc["CacheClusterId"], cc, tags={},
                          created=cc.get("CacheClusterCreateTime"))

    os_ = ctx.client("opensearch")
    names = [d["DomainName"] for d in ctx.call(lambda: os_.list_domain_names()["DomainNames"],
                                               "opensearch:ListDomainNames", [])]
    for i in range(0, len(names), 5):
        for d in ctx.call(lambda: os_.describe_domains(DomainNames=names[i:i + 5])["DomainStatusList"],
                          "opensearch:DescribeDomains", []):
            d["AccessPolicies"] = _json(d.get("AccessPolicies"))
            yield ctx.res("opensearch", "domain", d["ARN"], d["DomainName"], d, tags={})

    for cl in ctx.pages(ctx.client("redshift"), "describe_clusters", "Clusters"):
        yield ctx.res("redshift", "cluster",
                      ctx.arn("redshift", f"cluster:{cl['ClusterIdentifier']}"), cl["ClusterIdentifier"], cl,
                      created=cl.get("ClusterCreateTime"))

    for fs in ctx.pages(ctx.client("efs"), "describe_file_systems", "FileSystems"):
        yield ctx.res("efs", "file-system", fs.get("FileSystemArn") or ctx.arn("elasticfilesystem",
                      f"file-system/{fs['FileSystemId']}"), fs.get("Name") or fs["FileSystemId"], fs,
                      created=fs.get("CreationTime"))

    for p in ctx.pages(ctx.client("backup"), "list_backup_plans", "BackupPlansList"):
        yield ctx.res("backup", "plan", p["BackupPlanArn"], p["BackupPlanName"], p, tags={},
                      created=p.get("CreationDate"))


# ------------------------------------------------------------------------- app

@collector("app")
def app(ctx: Ctx) -> Iterator[Resource]:
    for api in ctx.pages(ctx.client("apigateway"), "get_rest_apis", "items"):
        api["policy"] = _json((api.get("policy") or "").replace('\\"', '"'))
        yield ctx.res("apigateway", "rest-api", ctx.arn("apigateway", f"/restapis/{api['id']}", account=""),
                      api["name"], api, tags=api.get("tags") or {}, created=api.get("createdDate"))
    for api in ctx.pages(ctx.client("apigatewayv2"), "get_apis", "Items"):
        yield ctx.res("apigateway", api.get("ProtocolType", "http").lower() + "-api",
                      ctx.arn("apigateway", f"/apis/{api['ApiId']}", account=""), api["Name"], api,
                      tags=api.get("Tags") or {}, created=api.get("CreatedDate"))

    sqs = ctx.client("sqs")
    for url in ctx.pages(sqs, "list_queues", "QueueUrls"):
        attrs = ctx.call(lambda: sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"],
                         "sqs:GetQueueAttributes", {})
        attrs["Policy"] = _json(attrs.get("Policy"))
        name = url.rsplit("/", 1)[-1]
        yield ctx.res("sqs", "queue", attrs.get("QueueArn") or ctx.arn("sqs", name), name, attrs, tags={})

    sns = ctx.client("sns")
    for t in ctx.pages(sns, "list_topics", "Topics"):
        attrs = ctx.call(lambda: sns.get_topic_attributes(TopicArn=t["TopicArn"])["Attributes"],
                         "sns:GetTopicAttributes", {})
        attrs["Policy"] = _json(attrs.get("Policy"))
        attrs.pop("EffectiveDeliveryPolicy", None)
        yield ctx.res("sns", "topic", t["TopicArn"], t["TopicArn"].rsplit(":", 1)[-1], attrs, tags={})

    for r in ctx.pages(ctx.client("events"), "list_rules", "Rules"):
        yield ctx.res("events", "rule", r["Arn"], r["Name"], r, tags={})
    for sm in ctx.pages(ctx.client("stepfunctions"), "list_state_machines", "stateMachines"):
        yield ctx.res("states", "state-machine", sm["stateMachineArn"], sm["name"], sm, tags={},
                      created=sm.get("creationDate"))
    for p in ctx.pages(ctx.client("cognito-idp"), "list_user_pools", "UserPools", MaxResults=60):
        yield ctx.res("cognito-idp", "user-pool", ctx.arn("cognito-idp", f"userpool/{p['Id']}"), p["Name"], p,
                      tags={}, created=p.get("CreationDate"))
    for a in ctx.pages(ctx.client("appsync"), "list_graphql_apis", "graphqlApis"):
        yield ctx.res("appsync", "graphql-api", a["arn"], a["name"], a, tags=a.get("tags") or {})
    for s in ctx.pages(ctx.client("cloudformation"), "describe_stacks", "Stacks"):
        s.pop("Parameters", None)   # parameters can carry secrets passed in by hand
        s.pop("Outputs", None)
        yield ctx.res("cloudformation", "stack", s["StackId"], s["StackName"], s, created=s.get("CreationTime"))
    for g in ctx.pages(ctx.client("logs"), "describe_log_groups", "logGroups"):
        arn = g["arn"][:-2] if g["arn"].endswith(":*") else g["arn"]
        yield ctx.res("logs", "log-group", arn, g["logGroupName"], g, tags={}, created=g.get("creationTime"))


# -------------------------------------------------------------------- security

@collector("security")
def security(ctx: Ctx) -> Iterator[Resource]:
    kms = ctx.client("kms")
    for k in ctx.pages(kms, "list_keys", "Keys"):
        meta = ctx.call(lambda: kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"], "kms:DescribeKey", None)
        if not meta or meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") == "PendingDeletion":
            continue
        meta["Policy"] = _json(ctx.call(lambda: kms.get_key_policy(KeyId=k["KeyId"], PolicyName="default")["Policy"],
                                        "kms:GetKeyPolicy", None))
        if meta.get("KeySpec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT":
            meta["RotationEnabled"] = ctx.call(
                lambda: kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"],
                "kms:GetKeyRotationStatus", None)
        yield ctx.res("kms", "key", meta["Arn"], meta.get("Description") or meta["KeyId"], meta, tags={},
                      created=meta.get("CreationDate"))

    sm = ctx.client("secretsmanager")
    for s in ctx.pages(sm, "list_secrets", "SecretList"):
        s["Policy"] = _json(ctx.call(lambda: sm.get_resource_policy(SecretId=s["ARN"]).get("ResourcePolicy"),
                                     "secretsmanager:GetResourcePolicy", None))
        yield ctx.res("secretsmanager", "secret", s["ARN"], s["Name"], s, created=s.get("CreatedDate"))

    acm = ctx.client("acm")
    key_types = ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"]
    for c in ctx.pages(acm, "list_certificates", "CertificateSummaryList", Includes={"keyTypes": key_types}):
        d = ctx.call(lambda: acm.describe_certificate(CertificateArn=c["CertificateArn"])["Certificate"],
                     "acm:DescribeCertificate", None)
        if d:
            yield ctx.res("acm", "certificate", d["CertificateArn"], d.get("DomainName", ""), d, tags={},
                          created=d.get("CreatedAt") or d.get("ImportedAt"))

    waf = ctx.client("wafv2")
    for scope in ("REGIONAL", "CLOUDFRONT") if ctx.region == "us-east-1" else ("REGIONAL",):
        for acl in ctx.call(lambda: waf.list_web_acls(Scope=scope)["WebACLs"], "wafv2:ListWebACLs", []):
            yield ctx.res("wafv2", "web-acl", acl["ARN"], acl["Name"], {**acl, "Scope": scope}, tags={})

    # Per-region detection settings, and the high-severity findings AWS has already made.
    settings: dict = {"Region": ctx.region}
    gd = ctx.client("guardduty")
    detectors = ctx.call(lambda: gd.list_detectors()["DetectorIds"], "guardduty:ListDetectors", None)
    settings["GuardDuty"] = None if detectors is None else "DISABLED"
    settings["GuardDutyFindings"] = []
    for det in detectors or []:
        status = ctx.call(lambda: gd.get_detector(DetectorId=det)["Status"], "guardduty:GetDetector", None)
        if status == "ENABLED":
            settings["GuardDuty"] = "ENABLED"
            ids = ctx.call(lambda: gd.list_findings(
                DetectorId=det, MaxResults=50,
                FindingCriteria={"Criterion": {"service.archived": {"Eq": ["false"]},
                                               "severity": {"Gte": 7}}})["FindingIds"],
                "guardduty:ListFindings", [])
            if ids:
                for f in ctx.call(lambda: gd.get_findings(DetectorId=det, FindingIds=ids)["Findings"],
                                  "guardduty:GetFindings", []):
                    settings["GuardDutyFindings"].append({
                        "Id": f["Id"], "Type": f["Type"], "Severity": f["Severity"],
                        "Title": f["Title"], "ResourceType": (f.get("Resource") or {}).get("ResourceType"),
                    })
    sh = ctx.client("securityhub")
    hub = ctx.call(lambda: sh.describe_hub().get("HubArn"), "securityhub:DescribeHub", None,
                   quiet=("InvalidAccessException", "ResourceNotFoundException"))
    settings["SecurityHub"] = bool(hub)
    settings["SecurityHubFindings"] = []
    if hub:
        found = ctx.call(lambda: sh.get_findings(MaxResults=100, Filters={
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"},
                               {"Value": "NOTIFIED", "Comparison": "EQUALS"}],
            "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"},
                              {"Value": "HIGH", "Comparison": "EQUALS"}],
        })["Findings"], "securityhub:GetFindings", [])
        for f in found:
            settings["SecurityHubFindings"].append({
                "Id": f["Id"], "Title": f.get("Title"), "Severity": (f.get("Severity") or {}).get("Label"),
                "Resource": ((f.get("Resources") or [{}])[0]).get("Id"),
                "Remediation": ((f.get("Remediation") or {}).get("Recommendation") or {}).get("Text"),
            })
    settings["EbsEncryptionByDefault"] = ctx.call(
        lambda: ctx.client("ec2").get_ebs_encryption_by_default()["EbsEncryptionByDefault"],
        "ec2:GetEbsEncryptionByDefault", None)
    yield ctx.res("account", "region-settings",
                  f"arn:{ctx.partition}:cloudlens:{ctx.region}:{ctx.account_id}:region-settings",
                  ctx.region, settings, tags={})


# ------------------------------------------------------------------- catch-all

def tagged_resources(ctx: Ctx) -> list[dict]:
    """Every taggable resource in the region the Tagging API knows about.

    Run after the specific collectors; anything they did not already return is kept
    as a generic resource, so a service cloudlens has no collector for still shows up.
    """
    return ctx.pages(ctx.client("resourcegroupstaggingapi"), "get_resources", "ResourceTagMappingList")


def generic(ctx: Ctx, item: dict) -> Resource:
    arn = item["ResourceARN"]
    parts = arn.split(":", 5)
    service = parts[2] if len(parts) > 2 else "unknown"
    rest = parts[5] if len(parts) > 5 else arn
    type_, _, name = rest.partition("/") if "/" in rest else rest.partition(":")
    return ctx.res(service, type_ or "resource", arn, name or rest, {"Source": "tagging-api"},
                   tags=tags_of(item.get("Tags")))
