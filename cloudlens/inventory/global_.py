"""Account-wide (non-regional) collectors: IAM, S3, Route 53, domains, CloudFront, CloudTrail."""
from __future__ import annotations

import csv
import io
import json
import time
from typing import Iterator
from urllib.parse import unquote

from .base import Ctx, Resource, collector, tags_of


def _doc(value) -> dict:
    """IAM policy documents arrive decoded by botocore, but be lenient with strings."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value:
        try:
            return json.loads(unquote(value))
        except ValueError:
            return {}
    return {}


def _credential_report(ctx: Ctx) -> list[dict]:
    iam = ctx.client("iam")
    for _ in range(10):
        state = ctx.call(lambda: iam.generate_credential_report()["State"], "iam:GenerateCredentialReport")
        if state == "COMPLETE" or state is None:
            break
        time.sleep(2)
    content = ctx.call(lambda: iam.get_credential_report()["Content"], "iam:GetCredentialReport",
                       quiet=("ReportNotPresent", "ReportInProgress"))
    if not content:
        return []
    text = content.decode() if isinstance(content, bytes) else content
    return list(csv.DictReader(io.StringIO(text)))


@collector("account", scope="global")
def account(ctx: Ctx) -> Iterator[Resource]:
    """One pseudo-resource per account holding account-level security settings."""
    iam = ctx.client("iam")
    report = _credential_report(ctx)
    raw = {
        "Summary": ctx.call(lambda: iam.get_account_summary()["SummaryMap"], "iam:GetAccountSummary", {}),
        "PasswordPolicy": ctx.call(lambda: iam.get_account_password_policy()["PasswordPolicy"],
                                   "iam:GetAccountPasswordPolicy", None, quiet=("NoSuchEntity",)),
        "S3PublicAccessBlock": ctx.call(
            lambda: ctx.client("s3control").get_public_access_block(
                AccountId=ctx.account_id)["PublicAccessBlockConfiguration"],
            "s3control:GetPublicAccessBlock", None, quiet=("NoSuchPublicAccessBlockConfiguration",)),
        "Root": next((r for r in report if r.get("user") == "<root_account>"), None),
        "Aliases": ctx.call(lambda: iam.list_account_aliases()["AccountAliases"], "iam:ListAccountAliases", []),
    }
    yield ctx.res("account", "account", f"arn:{ctx.partition}:iam::{ctx.account_id}:root",
                  (raw["Aliases"] or [ctx.account_id])[0], raw, tags={})
    # Stash the report for the IAM collector, which runs in the same pass.
    ctx.credential_report = {r["user"]: r for r in report}  # type: ignore[attr-defined]


@collector("iam", scope="global")
def iam(ctx: Ctx) -> Iterator[Resource]:
    client = ctx.client("iam")
    report = getattr(ctx, "credential_report", None)
    if report is None:
        report = {r["user"]: r for r in _credential_report(ctx)}

    details = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    def fetch():
        for page in client.get_paginator("get_account_authorization_details").paginate(
                Filter=["User", "Role", "Group", "LocalManagedPolicy"]):
            for k in details:
                details[k].extend(page.get(k) or [])
        return True
    if not ctx.call(fetch, "iam:GetAccountAuthorizationDetails", False):
        return

    for u in details["UserDetailList"]:
        for p in u.get("UserPolicyList") or []:
            p["PolicyDocument"] = _doc(p.get("PolicyDocument"))
        keys = ctx.call(lambda: client.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"],
                        "iam:ListAccessKeys", [])
        for k in keys:
            k["LastUsed"] = ctx.call(
                lambda: client.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])["AccessKeyLastUsed"],
                "iam:GetAccessKeyLastUsed", {})
        u["AccessKeys"] = keys
        u["MFADevices"] = ctx.call(lambda: client.list_mfa_devices(UserName=u["UserName"])["MFADevices"],
                                   "iam:ListMFADevices", [])
        u["CredentialReport"] = report.get(u["UserName"])
        yield ctx.res("iam", "user", u["Arn"], u["UserName"], u, created=u.get("CreateDate"))

    for g in details["GroupDetailList"]:
        for p in g.get("GroupPolicyList") or []:
            p["PolicyDocument"] = _doc(p.get("PolicyDocument"))
        yield ctx.res("iam", "group", g["Arn"], g["GroupName"], g, tags={}, created=g.get("CreateDate"))

    for r in details["RoleDetailList"]:
        r["AssumeRolePolicyDocument"] = _doc(r.get("AssumeRolePolicyDocument"))
        for p in r.get("RolePolicyList") or []:
            p["PolicyDocument"] = _doc(p.get("PolicyDocument"))
        r.pop("InstanceProfileList", None)
        yield ctx.res("iam", "role", r["Arn"], r["RoleName"], r, created=r.get("CreateDate"))

    for p in details["Policies"]:
        default = next((v for v in p.get("PolicyVersionList") or [] if v.get("IsDefaultVersion")), {})
        p["Document"] = _doc(default.get("Document"))
        p.pop("PolicyVersionList", None)
        yield ctx.res("iam", "policy", p["Arn"], p["PolicyName"], p, tags={}, created=p.get("CreateDate"))


@collector("s3", scope="global")
def s3(ctx: Ctx) -> Iterator[Resource]:
    base = ctx.client("s3")
    buckets = ctx.call(lambda: base.list_buckets()["Buckets"], "s3:ListBuckets", [])
    for b in buckets:
        name = b["Name"]
        loc = ctx.call(lambda: base.get_bucket_location(Bucket=name).get("LocationConstraint"),
                       "s3:GetBucketLocation", None)
        region = loc or "us-east-1"
        region = "eu-west-1" if region == "EU" else region
        s3r = ctx.client("s3", region)
        q = ("NoSuchBucketPolicy", "NoSuchPublicAccessBlockConfiguration", "NoSuchTagSet",
             "ServerSideEncryptionConfigurationNotFoundError", "NoSuchWebsiteConfiguration")
        policy = ctx.call(lambda: s3r.get_bucket_policy(Bucket=name)["Policy"], "s3:GetBucketPolicy", None, q)
        raw = {
            "Name": name,
            "Region": region,
            "CreationDate": b.get("CreationDate"),
            "Policy": json.loads(policy) if policy else None,
            "PolicyStatus": ctx.call(lambda: s3r.get_bucket_policy_status(Bucket=name)["PolicyStatus"],
                                     "s3:GetBucketPolicyStatus", None, q),
            "PublicAccessBlock": ctx.call(
                lambda: s3r.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"],
                "s3:GetPublicAccessBlock", None, q),
            "Acl": ctx.call(lambda: {k: v for k, v in s3r.get_bucket_acl(Bucket=name).items()
                                     if k in ("Grants", "Owner")}, "s3:GetBucketAcl", None),
            "Encryption": ctx.call(
                lambda: s3r.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"],
                "s3:GetBucketEncryption", None, q),
            "Versioning": ctx.call(lambda: s3r.get_bucket_versioning(Bucket=name).get("Status"),
                                   "s3:GetBucketVersioning", None),
            "Website": ctx.call(lambda: bool(s3r.get_bucket_website(Bucket=name)), "s3:GetBucketWebsite",
                                False, q),
        }
        tags = ctx.call(lambda: s3r.get_bucket_tagging(Bucket=name)["TagSet"], "s3:GetBucketTagging", [], q)
        yield ctx.res("s3", "bucket", f"arn:{ctx.partition}:s3:::{name}", name, raw,
                      tags=tags_of(tags), created=b.get("CreationDate"), region=region)


@collector("route53", scope="global")
def route53(ctx: Ctx) -> Iterator[Resource]:
    r53 = ctx.client("route53")
    for z in ctx.pages(r53, "list_hosted_zones", "HostedZones"):
        zid = z["Id"].split("/")[-1]
        records = ctx.pages(r53, "list_resource_record_sets", "ResourceRecordSets", HostedZoneId=zid)
        z["Records"] = [
            {"Name": r["Name"], "Type": r["Type"],
             "Values": [v["Value"] for v in r.get("ResourceRecords") or []],
             "Alias": (r.get("AliasTarget") or {}).get("DNSName")}
            for r in records[:5000]
        ]
        yield ctx.res("route53", "hosted-zone", f"arn:{ctx.partition}:route53:::hostedzone/{zid}",
                      z["Name"].rstrip("."), z, tags={})

    domains = ctx.client("route53domains", "us-east-1")
    for d in ctx.pages(domains, "list_domains", "Domains"):
        yield ctx.res("route53domains", "domain",
                      f"arn:{ctx.partition}:route53domains:::{ctx.account_id}/domain/{d['DomainName']}",
                      d["DomainName"], d, tags={})


@collector("cloudfront", scope="global")
def cloudfront(ctx: Ctx) -> Iterator[Resource]:
    cf = ctx.client("cloudfront")
    def run():
        out = []
        for page in cf.get_paginator("list_distributions").paginate():
            out.extend((page.get("DistributionList") or {}).get("Items") or [])
        return out
    for d in ctx.call(run, "cloudfront:ListDistributions", []):
        aliases = (d.get("Aliases") or {}).get("Items") or []
        yield ctx.res("cloudfront", "distribution", d["ARN"], aliases[0] if aliases else d["DomainName"],
                      d, tags={})


@collector("cloudtrail", scope="global")
def cloudtrail(ctx: Ctx) -> Iterator[Resource]:
    trails = ctx.call(lambda: ctx.client("cloudtrail").describe_trails(includeShadowTrails=True)["trailList"],
                      "cloudtrail:DescribeTrails", [])
    seen = set()
    for t in trails:
        if t["TrailARN"] in seen:
            continue
        seen.add(t["TrailARN"])
        home = t.get("HomeRegion") or ctx.home_region
        t["Status"] = ctx.call(
            lambda: ctx.client("cloudtrail", home).get_trail_status(Name=t["TrailARN"]),
            "cloudtrail:GetTrailStatus", {})
        t["Status"].pop("ResponseMetadata", None)
        yield ctx.res("cloudtrail", "trail", t["TrailARN"], t["Name"], t, tags={}, region=home)
