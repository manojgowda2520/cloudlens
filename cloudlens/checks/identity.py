"""IAM checks, plus the helpers other checks use to resolve what a role can do."""
from __future__ import annotations

from typing import Iterator

from . import policy
from .base import Hit, View, check

ADMIN_MANAGED = {"AdministratorAccess"}
BROAD_MANAGED = {"AdministratorAccess", "IAMFullAccess", "PowerUserAccess"}


def _managed_name(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


def documents(view: View, principal: dict) -> list[tuple[str, dict]]:
    """Every policy document attached to a user, role or group: (label, document).

    AWS-managed policies are not fetched (there are over a thousand); they are judged
    by name via `managed_names`.
    """
    raw = principal["raw"]
    docs = []
    for key in ("RolePolicyList", "UserPolicyList", "GroupPolicyList"):
        for p in raw.get(key) or []:
            docs.append((f"inline {p.get('PolicyName')}", p.get("PolicyDocument") or {}))
    local = {p["arn"]: p for p in view.of("iam", "policy")}
    for att in raw.get("AttachedManagedPolicies") or []:
        if att["PolicyArn"] in local:
            docs.append((f"policy {att['PolicyName']}", local[att["PolicyArn"]]["raw"].get("Document") or {}))
    return docs


def managed_names(principal: dict) -> set[str]:
    return {_managed_name(a["PolicyArn"]) for a in principal["raw"].get("AttachedManagedPolicies") or []
            if ":aws:policy/" in a["PolicyArn"]}


def admin_source(view: View, principal: dict) -> str:
    """Why this principal is admin, or '' if it is not."""
    hit = managed_names(principal) & ADMIN_MANAGED
    if hit:
        return f"attached AWS managed policy {sorted(hit)[0]}"
    for label, doc in documents(view, principal):
        if policy.is_admin(doc):
            return f"{label} allows Action:* on Resource:*"
    return ""


def role_by_arn(view: View, arn: str):
    for r in view.of("iam", "role"):
        if r["arn"] == arn:
            return r
    return None


def _service_managed(role: dict) -> bool:
    path = role["raw"].get("Path", "")
    name = role["raw"].get("RoleName", "")
    return path.startswith("/aws-service-role/") or path.startswith("/aws-reserved/") or \
        name.startswith("AWSReservedSSO_") or name.startswith("OrganizationAccountAccessRole")


# --------------------------------------------------------------------- account

@check("IAM-01", "Critical", "Root user has access keys",
       "Delete the root user's access keys and use IAM roles for programmatic access.")
def root_keys(view: View) -> Iterator[Hit]:
    acct = view.account()
    if not acct:
        return
    summary = acct["raw"].get("Summary") or {}
    root = acct["raw"].get("Root") or {}
    if summary.get("AccountAccessKeysPresent") or root.get("access_key_1_active") == "true" \
            or root.get("access_key_2_active") == "true":
        yield Hit(acct, "AccountAccessKeysPresent = 1")


@check("IAM-02", "Critical", "Root user has no MFA",
       "Enable MFA (ideally a hardware key) on the root user and lock the credentials away.")
def root_mfa(view: View) -> Iterator[Hit]:
    acct = view.account()
    if not acct:
        return
    summary = acct["raw"].get("Summary") or {}
    if "AccountMFAEnabled" in summary and not summary["AccountMFAEnabled"]:
        yield Hit(acct, "AccountMFAEnabled = 0")


@check("IAM-10", "Medium", "Weak or missing IAM password policy",
       "Set a password policy: minimum 14 characters, require symbols/numbers/upper/lower, prevent reuse.")
def password_policy(view: View) -> Iterator[Hit]:
    acct = view.account()
    if not acct or "Summary" not in acct["raw"]:
        return
    pp = acct["raw"].get("PasswordPolicy")
    if not pp:
        yield Hit(acct, "no account password policy is set")
        return
    weak = []
    if (pp.get("MinimumPasswordLength") or 0) < 14:
        weak.append(f"MinimumPasswordLength = {pp.get('MinimumPasswordLength')}")
    for k in ("RequireSymbols", "RequireNumbers", "RequireUppercaseCharacters", "RequireLowercaseCharacters"):
        if not pp.get(k):
            weak.append(f"{k} = false")
    if not pp.get("PasswordReusePrevention"):
        weak.append("PasswordReusePrevention not set")
    if weak:
        yield Hit(acct, "; ".join(weak))


# ----------------------------------------------------------------------- users

@check("IAM-03", "High", "Console user without MFA",
       "Enable MFA for this user, or remove console access if it is not needed.")
def user_mfa(view: View) -> Iterator[Hit]:
    for u in view.of("iam", "user"):
        rep = u["raw"].get("CredentialReport") or {}
        if rep.get("password_enabled") == "true" and rep.get("mfa_active") == "false":
            yield Hit(u, f"password_enabled = true, mfa_active = false, "
                         f"password_last_used = {rep.get('password_last_used')}")


@check("IAM-04", "Medium", "Access key older than 90 days",
       "Rotate the key: create a new one, switch the application over, then deactivate and delete the old one.")
def old_keys(view: View) -> Iterator[Hit]:
    for u in view.of("iam", "user"):
        for k in u["raw"].get("AccessKeys") or []:
            age = view.days_since(k.get("CreateDate"))
            if k.get("Status") == "Active" and age is not None and age > 90:
                yield Hit(u, f"{k['AccessKeyId'][:8]}… created {int(age)} days ago")


@check("IAM-05", "Medium", "Active access key unused for 90+ days",
       "Deactivate the key; delete it after confirming nothing breaks.")
def unused_keys(view: View) -> Iterator[Hit]:
    for u in view.of("iam", "user"):
        for k in u["raw"].get("AccessKeys") or []:
            if k.get("Status") != "Active":
                continue
            used = (k.get("LastUsed") or {}).get("LastUsedDate")
            idle = view.days_since(used) if used else view.days_since(k.get("CreateDate"))
            if idle is not None and idle > 90:
                what = f"last used {int(idle)} days ago" if used else f"never used, created {int(idle)} days ago"
                yield Hit(u, f"{k['AccessKeyId'][:8]}… {what}")


@check("IAM-06", "High", "IAM user has administrator access",
       "Give humans access through SSO roles instead of long-lived admin users; if the user must stay, scope it down.")
def admin_users(view: View) -> Iterator[Hit]:
    groups = {g["raw"].get("GroupName"): g for g in view.of("iam", "group")}
    for u in view.of("iam", "user"):
        why = admin_source(view, u)
        if not why:
            for gname in u["raw"].get("GroupList") or []:
                g = groups.get(gname)
                if g and admin_source(view, g):
                    why = f"via group {gname}: {admin_source(view, g)}"
                    break
        if why:
            yield Hit(u, why)


# ---------------------------------------------------------------------- policies

@check("IAM-07", "High", "Customer policy allows all actions on all resources",
       "Replace Action:* / Resource:* with the specific actions and resources the workload needs.")
def star_policies(view: View) -> Iterator[Hit]:
    for p in view.of("iam", "policy"):
        if policy.is_admin(p["raw"].get("Document")):
            n = p["raw"].get("AttachmentCount", 0)
            yield Hit(p, f"default version allows Action:* on Resource:*; attached to {n} entities",
                      severity="High" if n else "Low")
    for kind in ("user", "role", "group"):
        for e in view.of("iam", kind):
            if kind == "role" and _service_managed(e):
                continue
            for p in e["raw"].get(f"{kind.capitalize()}PolicyList") or []:
                if policy.is_admin(p.get("PolicyDocument")):
                    yield Hit(e, f"inline policy {p.get('PolicyName')} allows Action:* on Resource:*")


# ------------------------------------------------------------------------- roles

@check("IAM-08", "Critical", "Role can be assumed by anyone, or by another account without ExternalId",
       "Restrict the trust policy to specific principals; require sts:ExternalId for third parties and a "
       "'sub' condition for GitHub OIDC.")
def open_trust(view: View) -> Iterator[Hit]:
    known = view.shared.account_ids | {view.account_id}
    for r in view.of("iam", "role"):
        if _service_managed(r):
            continue
        doc = r["raw"].get("AssumeRolePolicyDocument") or {}
        for s in policy.public_statements(doc):
            yield Hit(r, f"trust policy: {policy.summarize(s)}")
            break
        else:
            for s in policy.statements(doc):
                if not policy.allows(s):
                    continue
                keys = policy.condition_keys(s)
                principal = s.get("Principal") or {}
                fed = policy._list(principal.get("Federated")) if isinstance(principal, dict) else []
                if any("token.actions.githubusercontent.com" in f for f in fed) and \
                        "token.actions.githubusercontent.com:sub" not in keys:
                    yield Hit(r, "GitHub OIDC trust without a 'sub' condition: any repository on "
                                 "GitHub can assume this role")
                    break
                foreign = policy.foreign_principals({"Statement": [s]}, view.account_id, known)
                if foreign and "sts:externalid" not in keys:
                    yield Hit(r, f"trusted by account(s) {', '.join(sorted(foreign))} without sts:ExternalId",
                              severity="High")
                    break


@check("IAM-09", "Low", "Role unused for 90+ days",
       "Delete roles nothing uses; unused permissions are pure attack surface.")
def unused_roles(view: View) -> Iterator[Hit]:
    for r in view.of("iam", "role"):
        if _service_managed(r):
            continue
        last = (r["raw"].get("RoleLastUsed") or {}).get("LastUsedDate")
        idle = view.days_since(last) if last else view.days_since(r["raw"].get("CreateDate"))
        if idle is not None and idle > 90:
            yield Hit(r, f"last used {int(idle)} days ago" if last else f"never used, created {int(idle)} days ago")
