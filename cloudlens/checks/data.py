"""Data-protection checks: encryption, public snapshots, backups, keys, secrets, resource policies."""
from __future__ import annotations

from typing import Iterator

from . import policy
from .base import Hit, View, check


def _is_prod(r: dict) -> bool:
    values = " ".join(str(v).lower() for k, v in r["tags"].items()
                      if k.lower() in ("env", "environment", "stage", "tier"))
    return "prod" in values or "prod" in r["name"].lower()


@check("DAT-01", "High", "Data store is not encrypted at rest",
       "Encryption at rest cannot be switched on in place for most services: snapshot, restore encrypted, cut over.")
def unencrypted(view: View) -> Iterator[Hit]:
    rules = [
        ("rds", "instance", lambda r: r.get("StorageEncrypted") is False, "StorageEncrypted = false"),
        ("rds", "cluster", lambda r: r.get("StorageEncrypted") is False, "StorageEncrypted = false"),
        ("ec2", "volume", lambda r: r.get("Encrypted") is False, "Encrypted = false"),
        ("efs", "file-system", lambda r: r.get("Encrypted") is False, "Encrypted = false"),
        ("redshift", "cluster", lambda r: r.get("Encrypted") is False, "Encrypted = false"),
        ("elasticache", "replication-group", lambda r: r.get("AtRestEncryptionEnabled") is False,
         "AtRestEncryptionEnabled = false"),
        ("opensearch", "domain", lambda r: (r.get("EncryptionAtRestOptions") or {}).get("Enabled") is False,
         "EncryptionAtRestOptions.Enabled = false"),
    ]
    for service, type_, bad, evidence in rules:
        for r in view.of(service, type_):
            if bad(r["raw"]):
                yield Hit(r, evidence, severity="Medium" if service == "ec2" else None)


@check("DAT-02", "Critical", "Snapshot or image is public",
       "Remove the 'all' permission: anyone with an AWS account can copy it and read the data.")
def public_snapshots(view: View) -> Iterator[Hit]:
    for s in view.of("ec2", "snapshot"):
        if s["raw"].get("Public"):
            yield Hit(s, f"EBS snapshot {s['raw'].get('SnapshotId')} restorable by all")
    for s in view.of("rds", "snapshot"):
        if s["raw"].get("Public"):
            yield Hit(s, "RDS snapshot restore attribute includes 'all'")
    for i in view.of("ec2", "image"):
        if i["raw"].get("Public"):
            yield Hit(i, f"AMI {i['raw'].get('ImageId')} is public", severity="High")


@check("DAT-03", "Medium", "Database has no backups or no deletion protection",
       "Set a backup retention period of 7+ days; turn on deletion protection for production databases.")
def rds_backups(view: View) -> Iterator[Hit]:
    for db in view.of("rds", "instance") + view.of("rds", "cluster"):
        raw = db["raw"]
        if raw.get("DBClusterIdentifier") and db["type"] == "instance":
            continue   # Aurora instances inherit backup settings from the cluster
        problems = []
        if raw.get("BackupRetentionPeriod") == 0:
            problems.append("BackupRetentionPeriod = 0")
        if _is_prod(db) and raw.get("DeletionProtection") is False:
            problems.append("DeletionProtection = false on a production database")
        if problems:
            yield Hit(db, "; ".join(problems))


@check("DAT-04", "High", "KMS key policy allows any principal",
       "Restrict the key policy to named principals or add aws:PrincipalOrgID / kms:CallerAccount conditions.")
def kms_public(view: View) -> Iterator[Hit]:
    for k in view.of("kms", "key"):
        stmts = policy.public_statements(k["raw"].get("Policy"))
        if stmts:
            yield Hit(k, policy.summarize(stmts[0]))


@check("DAT-05", "Low", "Secret not rotated in 180 days",
       "Turn on automatic rotation, or rotate it by hand and record when.")
def secret_rotation(view: View) -> Iterator[Hit]:
    for s in view.of("secretsmanager", "secret"):
        raw = s["raw"]
        if raw.get("RotationEnabled"):
            continue
        last = raw.get("LastRotatedDate") or raw.get("LastChangedDate") or raw.get("CreatedDate")
        age = view.days_since(last)
        if age is not None and age > 180:
            yield Hit(s, f"rotation off; last changed {int(age)} days ago")


@check("DAT-06", "Low", "Customer KMS key has rotation off",
       "Enable automatic key rotation.")
def kms_rotation(view: View) -> Iterator[Hit]:
    for k in view.of("kms", "key"):
        if k["raw"].get("RotationEnabled") is False and k["raw"].get("KeyState") == "Enabled":
            yield Hit(k, "KeyRotationEnabled = false")


@check("DAT-07", "High", "Queue, topic, repository or secret is open to anyone",
       "Restrict the resource policy to named principals or add a SourceArn/SourceAccount/PrincipalOrgID condition.")
def public_resource_policies(view: View) -> Iterator[Hit]:
    for service, type_, key in (("sqs", "queue", "Policy"), ("sns", "topic", "Policy"),
                                ("ecr", "repository", "Policy"), ("secretsmanager", "secret", "Policy")):
        for r in view.of(service, type_):
            stmts = policy.public_statements(r["raw"].get(key))
            if stmts:
                yield Hit(r, policy.summarize(stmts[0]), severity="Medium" if service == "ecr" else None)


@check("DAT-08", "Critical", "OpenSearch domain is open to the internet",
       "Move the domain into a VPC, or restrict its access policy to specific IAM principals/IPs.")
def opensearch_public(view: View) -> Iterator[Hit]:
    for d in view.of("opensearch", "domain"):
        if not d["raw"].get("VPCOptions") and policy.public_statements(d["raw"].get("AccessPolicies")):
            yield Hit(d, f"public endpoint {d['raw'].get('Endpoint')} with an access policy open to '*'")


@check("DAT-09", "High", "Redshift cluster is publicly accessible",
       "Set PubliclyAccessible to false and connect through the VPC.")
def redshift_public(view: View) -> Iterator[Hit]:
    for c in view.of("redshift", "cluster"):
        if c["raw"].get("PubliclyAccessible"):
            yield Hit(c, "PubliclyAccessible = true")
