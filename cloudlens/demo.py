"""A synthetic estate for `cloudlens serve --demo`, screenshots and UI tests.

Nothing here is real: account IDs are the documented fakes, domains are under the
reserved example.* names, and every value is generated from a fixed seed. Findings are
not hard-coded - the fake inventory goes through the real checks, so the demo also
exercises them.
"""
from __future__ import annotations

import random
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .checks.base import Shared, View, run_checks
from .inventory.base import Resource
from .store import Store

NOW = datetime.now(timezone.utc)

PORTALS = [
    ("northwind", "Northwind Mobility", "https://northwind-demo.awsapps.com/start", "ap-south-1", [
        ("111111111111", "mobility-prod", 2.6), ("222222222222", "mobility-staging", 0.8),
        ("333333333333", "mobility-dev", 0.5), ("444444444444", "shared-services", 0.9),
        ("555555555555", "data-platform", 1.7)]),
    ("fleetops", "Client: FleetOps", "https://fleetops-demo.awsapps.com/start", "eu-west-1", [
        ("666666666666", "fleetops-prod", 1.2), ("777777777777", "fleetops-dev", 0.3)]),
    ("lab", "Personal lab", "https://lab-demo.awsapps.com/start", "us-east-1", [
        ("888888888888", "devops-lab", 0.1)]),
]

SERVICES_COST = [("Amazon Elastic Compute Cloud - Compute", 38), ("Amazon Relational Database Service", 22),
                 ("AWS Lambda", 6), ("Amazon Simple Storage Service", 7), ("Amazon CloudFront", 5),
                 ("Amazon DynamoDB", 4), ("Amazon Virtual Private Cloud", 6), ("AmazonCloudWatch", 4),
                 ("Elastic Load Balancing", 5), ("AWS Key Management Service", 1), ("Amazon Route 53", 1)]


def _iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat(timespec="seconds")


class _Gen:
    def __init__(self, account: str, name: str, scale: float, rnd: random.Random, variant: int):
        self.a, self.name, self.scale, self.r, self.v = account, name, scale, rnd, variant
        self.out: list[Resource] = []
        self.regions = ["ap-south-1", "us-east-1"] if "fleetops" not in name else ["eu-west-1", "us-east-1"]
        self.prod = "prod" in name

    def add(self, service, type_, arn, name, raw, region, tags=None, created=None):
        self.out.append(Resource(arn=arn, account_id=self.a, region=region, service=service, type=type_,
                                 name=name, raw=raw, tags=tags or {}, created=created))

    def n(self, base: int) -> int:
        return max(1, int(base * self.scale * self.r.uniform(0.7, 1.3)))

    def build(self) -> list[Resource]:
        r, a = self.r, self.a
        env = "prod" if self.prod else ("staging" if "staging" in self.name else "dev")
        tags = {"env": env, "team": r.choice(["rides", "payments", "platform", "data"])}
        weak = not self.prod or "fleetops" in self.name   # dev accounts get sloppier settings

        # Account-level settings
        self.add("account", "account", f"arn:aws:iam::{a}:root", self.name, {
            "Summary": {"AccountMFAEnabled": 0 if self.name == "devops-lab" else 1,
                        "AccountAccessKeysPresent": 1 if self.name == "fleetops-dev" else 0},
            "PasswordPolicy": None if weak else {"MinimumPasswordLength": 14, "RequireSymbols": True,
                                                 "RequireNumbers": True, "RequireUppercaseCharacters": True,
                                                 "RequireLowercaseCharacters": True, "PasswordReusePrevention": 24},
            "S3PublicAccessBlock": None if weak else {k: True for k in (
                "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")},
            "Aliases": [self.name]}, "global")
        for region in self.regions:
            self.add("account", "region-settings", f"arn:aws:cloudlens:{region}:{a}:region-settings", region, {
                "Region": region, "GuardDuty": "ENABLED" if self.prod or region == "us-east-1" else "DISABLED",
                "SecurityHub": self.prod, "GuardDutyFindings": [{
                    "Id": "demo1", "Type": "UnauthorizedAccess:EC2/SSHBruteForce", "Severity": 8.0,
                    "Title": "SSH brute force against i-0demo", "ResourceType": "Instance"}]
                if self.name == "mobility-prod" and region == "ap-south-1" and self.v else [],
                "SecurityHubFindings": [], "EbsEncryptionByDefault": not weak}, region)
        self.add("cloudtrail", "trail", f"arn:aws:cloudtrail:us-east-1:{a}:trail/org-trail", "org-trail",
                 {"Name": "org-trail", "IsMultiRegionTrail": self.name != "devops-lab",
                  "Status": {"IsLogging": True}}, "us-east-1")

        # IAM
        admin = {"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "PolicyName": "AdministratorAccess"}
        lambda_trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        for i, person in enumerate(["ci-deployer", "ravi.k", "priya.s", "legacy-backup", "grafana-reader"][: 2 + self.n(2)]):
            human = "." in person
            keys = [] if human else [{"AccessKeyId": f"AKIADEMO{a[:4]}{i:08d}", "Status": "Active",
                                      "CreateDate": _iso(r.choice([30, 140, 420])),
                                      "LastUsed": {"LastUsedDate": _iso(r.choice([1, 2, 200]))}}]
            self.add("iam", "user", f"arn:aws:iam::{a}:user/{person}", person, {
                "UserName": person, "CreateDate": _iso(500), "GroupList": [],
                "AttachedManagedPolicies": [admin] if person in ("ci-deployer", "legacy-backup") else [],
                "UserPolicyList": [], "AccessKeys": keys,
                "CredentialReport": {"password_enabled": "true" if human else "false",
                                     "mfa_active": "false" if human and weak else "true"}}, "global")
        roles = []
        for role, policies in (("api-lambda-role", [admin] if weak else []), ("etl-lambda-role", []),
                               ("ops-readonly", [])):
            inline = [] if role != "etl-lambda-role" else [{"PolicyName": "etl", "PolicyDocument": {
                "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:*", "iam:PassRole"],
                                                        "Resource": "*"}]}}]
            arn = f"arn:aws:iam::{a}:role/{role}"
            roles.append(arn)
            self.add("iam", "role", arn, role, {
                "RoleName": role, "Path": "/", "CreateDate": _iso(300), "AssumeRolePolicyDocument": lambda_trust,
                "AttachedManagedPolicies": policies, "RolePolicyList": inline,
                "RoleLastUsed": {"LastUsedDate": _iso(1 if role != "ops-readonly" else 160)}}, "global")
        if self.name in ("shared-services", "fleetops-prod"):
            self.add("iam", "role", f"arn:aws:iam::{a}:role/vendor-monitoring", "vendor-monitoring", {
                "RoleName": "vendor-monitoring", "Path": "/", "CreateDate": _iso(400),
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"}]},
                "AttachedManagedPolicies": [], "RolePolicyList": [], "RoleLastUsed": {"LastUsedDate": _iso(3)}}, "global")
        if self.name == "mobility-dev":
            self.add("iam", "role", f"arn:aws:iam::{a}:role/github-deploy", "github-deploy", {
                "RoleName": "github-deploy", "Path": "/", "CreateDate": _iso(90),
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Federated": f"arn:aws:iam::{a}:oidc-provider/token.actions.githubusercontent.com"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}}]},
                "AttachedManagedPolicies": [admin], "RolePolicyList": [], "RoleLastUsed": {"LastUsedDate": _iso(1)}}, "global")

        # Lambda
        runtimes = ["python3.12", "nodejs20.x", "python3.9", "nodejs22.x", "python3.13", "java21"]
        for i in range(self.n(9)):
            fn = r.choice(["trip-pricing", "driver-match", "eta-calc", "payout-batch", "otp-sender", "geo-index",
                           "invoice-pdf", "surge-model", "fleet-sync", "webhook-relay"]) + f"-{i}"
            env_hits = [{"name": "DB_PASSWORD", "kind": "sensitive-name"}] if weak and i == 0 else []
            region = r.choice(self.regions)
            arn = f"arn:aws:lambda:{region}:{a}:function:{fn}"
            self.add("lambda", "function", arn, fn, {
                "FunctionName": fn, "FunctionArn": arn, "Runtime": r.choice(runtimes) if i else "python3.9",
                "Role": roles[i % 2], "MemorySize": r.choice([128, 256, 512, 1024]),
                "Environment": {"Variables": {"STAGE": "<redacted>", "DB_PASSWORD": "<redacted>"} if env_hits else {"STAGE": "<redacted>"}},
                "SecretHits": env_hits,
                "Policy": {"Version": "2012-10-17", "Statement": [{"Sid": "public", "Effect": "Allow", "Principal": "*",
                                                                    "Action": "lambda:InvokeFunction", "Resource": arn}]}
                if fn.startswith("webhook-relay") and weak else None,
                "UrlConfigs": [{"FunctionUrl": f"https://{fn}.lambda-url.{region}.on.aws/", "AuthType": "NONE"}]
                if fn.startswith("webhook") or (weak and i == 1) else [],
                "Invocations90d": 0 if i == 5 else r.randint(10, 9_000_000)}, region, tags, _iso(r.randint(5, 600)))

        # S3
        for b in ["assets", "trip-logs", "invoices", "backups", "static-site", "athena-results"][: 2 + self.n(3)]:
            bname = f"{self.name}-{b}"
            public = b == "static-site" or (weak and b == "trip-logs" and self.v)
            pol = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                                           "Resource": f"arn:aws:s3:::{bname}/*"}]} if public else \
                {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*",
                                                         "Resource": f"arn:aws:s3:::{bname}/*",
                                                         "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
            self.add("s3", "bucket", f"arn:aws:s3:::{bname}", bname, {
                "Name": bname, "Policy": pol, "PolicyStatus": {"IsPublic": public},
                "PublicAccessBlock": None if public else {k: True for k in (
                    "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")},
                "Acl": {"Grants": []}, "Encryption": {"Rules": [{}]},
                "Versioning": "Enabled" if b in ("backups", "invoices") else None,
                "Website": b == "static-site"}, self.regions[0], tags, _iso(r.randint(30, 900)))

        # Network + compute
        for region in self.regions:
            vpc = f"vpc-{a[:4]}{region[-1]}0"
            self.add("ec2", "vpc", f"arn:aws:ec2:{region}:{a}:vpc/{vpc}", f"{env}-vpc",
                     {"VpcId": vpc, "FlowLogs": self.prod}, region, tags)
            open_ssh = weak and region == self.regions[0]
            for g, perms in (("web-alb", [(443, "0.0.0.0/0"), (80, "0.0.0.0/0")]),
                             ("bastion", [(22, "0.0.0.0/0" if open_ssh else "10.0.0.0/8")]),
                             ("db", [(5432, "0.0.0.0/0" if self.name == "fleetops-dev" else "10.0.0.0/16")])):
                gid = f"sg-{a[:6]}{region[-1]}{g[:3]}"
                self.add("ec2", "security-group", f"arn:aws:ec2:{region}:{a}:security-group/{gid}", f"{g} ({gid})", {
                    "GroupId": gid, "GroupName": g, "VpcId": vpc, "InUse": True, "IpPermissionsEgress": [],
                    "IpPermissions": [{"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": c}]}
                                      for p, c in perms]}, region)
            for i in range(self.n(4)):
                iid = f"i-0{a[:4]}{region[-1]}{i:06d}"
                stopped = i == 3
                imds1 = weak and i == 0
                self.add("ec2", "instance", f"arn:aws:ec2:{region}:{a}:instance/{iid}", f"{env}-app-{i}", {
                    "InstanceId": iid, "InstanceType": r.choice(["t3.medium", "m6i.large", "c6g.xlarge"]),
                    "State": {"Name": "stopped" if stopped else "running"},
                    "MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "optional" if imds1 else "required"},
                    "PublicIpAddress": "203.0.113.%d" % (10 + i) if imds1 else None}, region, tags, _iso(r.randint(10, 400)))
                vid = f"vol-0{a[:4]}{region[-1]}{i:06d}"
                self.add("ec2", "volume", f"arn:aws:ec2:{region}:{a}:volume/{vid}", vid, {
                    "VolumeId": vid, "Size": r.choice([30, 100, 200]), "VolumeType": "gp3", "State": "in-use",
                    "Encrypted": not (weak and i == 1), "Attachments": [{"InstanceId": iid}]}, region, tags)
            if weak:
                vid = f"vol-0{a[:4]}{region[-1]}orphan"
                self.add("ec2", "volume", f"arn:aws:ec2:{region}:{a}:volume/{vid}", vid, {
                    "VolumeId": vid, "Size": 500, "VolumeType": "gp2", "State": "available", "Encrypted": True,
                    "Attachments": []}, region)
                self.add("ec2", "elastic-ip", f"arn:aws:ec2:{region}:{a}:elastic-ip/eipalloc-{a[:6]}",
                         "198.51.100.7", {"PublicIp": "198.51.100.7", "AllocationId": f"eipalloc-{a[:6]}"}, region)
            for i in range(self.n(3)):
                sid = f"snap-0{a[:4]}{region[-1]}{i:05d}"
                self.add("ec2", "snapshot", f"arn:aws:ec2:{region}:{a}:snapshot/{sid}", sid, {
                    "SnapshotId": sid, "VolumeSize": 200, "StartTime": _iso(r.choice([20, 250, 700])),
                    "Public": self.name == "data-platform" and i == 0}, region)
            lb = f"arn:aws:elasticloadbalancing:{region}:{a}:loadbalancer/app/{env}-alb/{a[:8]}"
            self.add("elbv2", "application", lb, f"{env}-alb", {
                "LoadBalancerArn": lb, "LoadBalancerName": f"{env}-alb", "Scheme": "internet-facing",
                "DNSName": f"{env}-alb-{a[:6]}.{region}.elb.amazonaws.com", "TargetGroupCount": 2,
                "TargetCount": 0 if (weak and region == "us-east-1") else 4,
                "Listeners": [{"Protocol": "HTTPS", "Port": 443, "SslPolicy": "ELBSecurityPolicy-2016-08" if weak else
                               "ELBSecurityPolicy-TLS13-1-2-2021-06"},
                              {"Protocol": "HTTP", "Port": 80, "DefaultActions": [{"Type": "redirect"}]}]}, region, tags)
            for t in ("trips", "drivers", "sessions")[: self.n(2)]:
                tn = f"{env}-{t}"
                self.add("dynamodb", "table", f"arn:aws:dynamodb:{region}:{a}:table/{tn}", tn,
                         {"TableName": tn, "ItemCount": r.randint(1000, 9_000_000)}, region, tags)
            self.add("logs", "log-group", f"arn:aws:logs:{region}:{a}:log-group:/aws/lambda/{env}", f"/aws/lambda/{env}",
                     {"retentionInDays": None if weak else 30, "storedBytes": r.randint(1, 60) * 10**9}, region)
            self.add("sqs", "queue", f"arn:aws:sqs:{region}:{a}:{env}-events", f"{env}-events",
                     {"QueueArn": f"arn:aws:sqs:{region}:{a}:{env}-events", "Policy": None}, region)

        # Databases
        db_region = self.regions[0]
        for i in range(self.n(2)):
            dbid = f"{env}-pg-{i}"
            self.add("rds", "instance", f"arn:aws:rds:{db_region}:{a}:db:{dbid}", dbid, {
                "DBInstanceIdentifier": dbid, "Engine": "postgres", "PubliclyAccessible": self.name == "fleetops-dev",
                "StorageEncrypted": not (weak and i == 0), "BackupRetentionPeriod": 0 if self.name == "mobility-dev" else 7,
                "DeletionProtection": self.prod and i == 0, "Endpoint": {"Address": f"{dbid}.demo.{db_region}.rds.amazonaws.com"}},
                db_region, tags, _iso(300))

        # Keys, secrets, certificates, DNS
        self.add("kms", "key", f"arn:aws:kms:{db_region}:{a}:key/{a[:8]}-demo", f"{env} data key", {
            "KeyId": f"{a[:8]}-demo", "KeyState": "Enabled", "RotationEnabled": not weak, "Policy": None}, db_region)
        self.add("secretsmanager", "secret", f"arn:aws:secretsmanager:{db_region}:{a}:secret:{env}/db", f"{env}/db", {
            "Name": f"{env}/db", "RotationEnabled": self.prod, "LastChangedDate": _iso(40 if self.prod else 400)}, db_region)
        if self.name in ("mobility-prod", "fleetops-prod", "shared-services"):
            dom = {"mobility-prod": "ride-demo.example", "fleetops-prod": "fleetops-demo.example",
                   "shared-services": "status-demo.example"}[self.name]
            self.add("route53domains", "domain", f"arn:aws:route53domains:::{a}/domain/{dom}", dom, {
                "DomainName": dom, "AutoRenew": self.name != "shared-services", "TransferLock": self.name != "fleetops-prod",
                "Expiry": _iso(-20 if self.name == "shared-services" else -300)}, "global")
            cf = f"d{a[:6]}demo.cloudfront.net"
            self.add("cloudfront", "distribution", f"arn:aws:cloudfront::{a}:distribution/E{a[:6]}", f"www.{dom}", {
                "ARN": f"arn:aws:cloudfront::{a}:distribution/E{a[:6]}", "DomainName": cf,
                "DefaultCacheBehavior": {"ViewerProtocolPolicy": "redirect-to-https" if self.prod else "allow-all"},
                "ViewerCertificate": {"MinimumProtocolVersion": "TLSv1.2_2021"}}, "global")
            records = [{"Name": f"www.{dom}.", "Type": "A", "Values": [], "Alias": cf},
                       {"Name": f"api.{dom}.", "Type": "CNAME", "Values": [f"prod-alb-{a[:6]}.{db_region}.elb.amazonaws.com"]}]
            if self.name == "fleetops-prod":
                records.append({"Name": f"promo.{dom}.", "Type": "CNAME",
                                "Values": ["fleetops-promo-2024.s3-website.eu-west-1.amazonaws.com"]})
            self.add("route53", "hosted-zone", f"arn:aws:route53:::hostedzone/Z{a[:8]}", dom,
                     {"Name": dom + ".", "Config": {"PrivateZone": False}, "Records": records}, "global")
            self.add("acm", "certificate", f"arn:aws:acm:us-east-1:{a}:certificate/{a[:8]}", f"*.{dom}", {
                "DomainName": f"*.{dom}", "NotAfter": _iso(-12 if self.name == "fleetops-prod" else -200),
                "InUseBy": [f"arn:aws:cloudfront::{a}:distribution/E{a[:6]}"],
                "RenewalSummary": {"RenewalStatus": "FAILED"} if self.name == "fleetops-prod" else None}, "us-east-1")
        return self.out


def build(path: Path, seed: int = 7) -> None:
    path = Path(path)
    for suffix in ("", "-wal", "-shm"):
        Path(str(path) + suffix).unlink(missing_ok=True)
    store = Store(path)
    rnd = random.Random(seed)
    accounts = []
    for pid, pname, url, region, accts in PORTALS:
        store.add_portal(pid, pname, url, region)
        for acct, name, scale in accts:
            role = "AdministratorAccess" if pid != "northwind" else "ReadOnlyAccess"
            store.upsert_discovered(pid, acct, name, f"aws+{name}@example.com", sorted({role, "ReadOnlyAccess"}))
            store.set_account(acct, enabled=True, role_name=role)
            accounts.append((acct, name, scale))

    # Two scans a week apart, so "what changed" has something to show.
    for variant, started in ((0, time.time() - 7 * 86400), (1, time.time() - 3600)):
        scan_id = store.start_scan(["inventory", "security", "cost"])
        store.x("UPDATE scans SET started_at=? WHERE id=?", (started, scan_id))
        all_res = {}
        for acct, name, scale in accounts:
            res = _Gen(acct, name, scale, random.Random(f"{seed}-{acct}"), variant).build()
            store.add_resources(scan_id, res)
            all_res[acct] = res
        shared = Shared(account_ids={a for a, _, _ in accounts})
        for res in all_res.values():
            for r in res:
                if r.type == "bucket":
                    shared.bucket_names.add(r.name)
                elif r.type == "distribution":
                    shared.cloudfront_domains.add(r.raw["DomainName"])
                elif r.service == "elbv2":
                    shared.elb_dns_names.add(r.raw["DNSName"])
        for acct in all_res:
            view = View.from_rows(acct, store.resources(scan_id, acct), shared)
            store.add_findings(scan_id, run_checks(view))
        if variant:
            store.add_scan_errors(scan_id, [
                ("777777777777", "ap-southeast-1", "databases rds:DescribeDBInstances",
                 "AccessDenied: User is not authorized to perform rds:DescribeDBInstances (SCP)")])
            store.add_resource_costs(scan_id, [
                (acct, "ap-south-1", svc, rid, rate, "realtime") for acct, svc, rid, rate in [
                    ("111111111111", "rds", "prod-pg-0", 0.712), ("111111111111", "ec2", "i-01111a000001", 0.384),
                    ("555555555555", "natgateway", "nat-0demo5555", 0.214), ("111111111111", "lambda", "trip-pricing-2", 0.166),
                    ("666666666666", "elb", "prod-alb", 0.061)]])
        store.finish_scan(scan_id, "partial" if variant else "ok",
                          f"{len(accounts)}/{len(accounts)} accounts reachable")
        store.x("UPDATE scans SET finished_at=? WHERE id=?", (started + 140 + 30 * variant, scan_id))

    # Cost: 60 days of daily spend per account and service.
    today = date.today()
    for acct, _name, scale in accounts:
        daily = []
        for d in range(60, -1, -1):
            day = today - timedelta(days=d)
            for svc, base in SERVICES_COST:
                usd = base * scale * rnd.uniform(0.85, 1.15) * (1.35 if d < 6 and acct == "555555555555" else 1)
                daily.append((day.isoformat(), svc, round(usd, 2)))
        mtd = sum(u for dd, _, u in daily if dd >= today.replace(day=1).isoformat())
        days_left = ((today.replace(day=28) + timedelta(days=4)).replace(day=1) - today).days
        store.save_cost(acct, daily, round(mtd + days_left * sum(b for _, b in SERVICES_COST) * scale, 2))

    calls = []
    t0 = time.time() - 3600
    for i in range(400):
        acct = accounts[i % len(accounts)][0]
        svc, op = rnd.choice([("ec2", "DescribeInstances"), ("lambda", "ListFunctions"), ("iam", "GetAccountAuthorizationDetails"),
                              ("s3", "GetBucketPolicy"), ("rds", "DescribeDBInstances"), ("ce", "GetCostAndUsage"),
                              ("ec2", "DescribeSecurityGroups"), ("kms", "DescribeKey")])
        outcome = "http 403" if svc == "rds" and acct == "777777777777" else "ok"
        calls.append((t0 + i * 8, "demo", acct, rnd.choice(["ap-south-1", "us-east-1", "eu-west-1"]), svc, op, outcome, ""))
    store.record_api_calls(calls)
    store.suppress("S3-01", "arn:aws:s3:::mobility-prod-static-site", "Public marketing site, served on purpose")
    store.close()
