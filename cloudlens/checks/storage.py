"""S3 checks."""
from __future__ import annotations

from typing import Iterator

from . import policy
from .base import Hit, View, check

_PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
_PUBLIC_GROUPS = ("http://acs.amazonaws.com/groups/global/AllUsers",
                  "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")


def _account_pab(view: View) -> dict:
    acct = view.account()
    return (acct["raw"].get("S3PublicAccessBlock") if acct else None) or {}


def _pab(view: View, bucket: dict, key: str) -> bool:
    return bool(_account_pab(view).get(key) or (bucket["raw"].get("PublicAccessBlock") or {}).get(key))


def _is_prod(r: dict) -> bool:
    values = " ".join(str(v).lower() for k, v in r["tags"].items()
                      if k.lower() in ("env", "environment", "stage", "tier"))
    return "prod" in values or "prod" in r["name"].lower()


@check("S3-01", "Critical", "S3 bucket is publicly accessible",
       "Remove the public statement or ACL grant and turn on Block Public Access; serve public content "
       "through CloudFront with Origin Access Control instead.")
def bucket_public(view: View) -> Iterator[Hit]:
    for b in view.of("s3", "bucket"):
        raw = b["raw"]
        reasons = []
        # AWS's own verdict (PolicyStatus) is authoritative when present; our statement
        # analysis covers accounts or regions where that call is unavailable.
        stmts = policy.public_statements(raw.get("Policy"))
        if ((raw.get("PolicyStatus") or {}).get("IsPublic") or stmts) and \
                not _pab(view, b, "RestrictPublicBuckets"):
            reasons.append("bucket policy is public" + (f": {policy.summarize(stmts[0])}" if stmts else ""))
        grants = [g for g in (raw.get("Acl") or {}).get("Grants") or []
                  if (g.get("Grantee") or {}).get("URI") in _PUBLIC_GROUPS]
        if grants and not _pab(view, b, "IgnorePublicAcls"):
            reasons.append("ACL grants " + ", ".join(
                f"{g['Permission']} to {g['Grantee']['URI'].rsplit('/', 1)[-1]}" for g in grants))
        if reasons:
            website = raw.get("Website")
            yield Hit(b, "; ".join(reasons) + ("; static website hosting is on - may be intentional" if website else ""),
                      severity="High" if website else None)


@check("S3-02", "High", "Account-level S3 Block Public Access is not fully on",
       "Turn on all four account-level Block Public Access settings unless a bucket must be public.")
def account_pab(view: View) -> Iterator[Hit]:
    acct = view.account()
    if not acct or "S3PublicAccessBlock" not in acct["raw"]:
        return
    cfg = _account_pab(view)
    off = [k for k in _PAB_KEYS if not cfg.get(k)]
    if off:
        yield Hit(acct, "not set: " + ", ".join(off) if cfg else "no account-level Block Public Access configuration")


@check("S3-03", "Medium", "Bucket Block Public Access is not fully on",
       "Turn on all four Block Public Access settings on the bucket.")
def bucket_pab(view: View) -> Iterator[Hit]:
    for b in view.of("s3", "bucket"):
        off = [k for k in _PAB_KEYS if not _pab(view, b, k)]
        if off:
            yield Hit(b, "not set (bucket or account): " + ", ".join(off))


@check("S3-04", "Low", "Bucket has no default encryption",
       "Set default encryption (SSE-S3 at minimum, SSE-KMS for sensitive data).")
def bucket_encryption(view: View) -> Iterator[Hit]:
    for b in view.of("s3", "bucket"):
        if "Encryption" in b["raw"] and not b["raw"]["Encryption"]:
            yield Hit(b, "no ServerSideEncryptionConfiguration")


@check("S3-05", "Medium", "Bucket policy does not enforce TLS",
       "Add a Deny statement for all principals when aws:SecureTransport is false.")
def bucket_tls(view: View) -> Iterator[Hit]:
    for b in view.of("s3", "bucket"):
        enforced = any(
            s.get("Effect") == "Deny" and "aws:securetransport" in policy.condition_keys(s)
            for s in policy.statements(b["raw"].get("Policy")))
        if not enforced:
            yield Hit(b, "no Deny on aws:SecureTransport = false")


@check("S3-06", "Low", "Production bucket has versioning off",
       "Enable versioning so overwritten or deleted objects can be recovered.")
def bucket_versioning(view: View) -> Iterator[Hit]:
    for b in view.of("s3", "bucket"):
        if _is_prod(b) and b["raw"].get("Versioning") != "Enabled":
            yield Hit(b, f"versioning = {b['raw'].get('Versioning') or 'never enabled'}")


@check("S3-07", "Info", "Bucket policy grants access to an outside account",
       "Confirm each external account is expected; remove grants nobody can explain.")
def bucket_cross_account(view: View) -> Iterator[Hit]:
    for b in view.of("s3", "bucket"):
        foreign = policy.foreign_principals(b["raw"].get("Policy"), view.account_id, view.shared.account_ids)
        if foreign:
            yield Hit(b, "external accounts: " + ", ".join(sorted(foreign)))
