"""IAM / resource-policy analysis helpers.

Deliberately conservative: these answer "does this statement, read literally, grant
X?" without evaluating permission boundaries, SCPs or session policies. That can
over-report (an SCP may block it) but never under-reports what the policy itself says.
"""
from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any, Iterator

# Condition keys that scope a "Principal: *" statement to something specific. A public
# principal with any of these is treated as restricted, not public.
RESTRICTING_KEYS = {
    "aws:sourcearn", "aws:sourceaccount", "aws:sourceowner", "aws:sourceorgid",
    "aws:sourceorgpaths", "aws:principalorgid", "aws:principalorgpaths",
    "aws:principalaccount", "aws:principalarn", "aws:sourcevpc", "aws:sourcevpce",
    "aws:sourceip", "aws:userid", "aws:username", "kms:calleraccount", "kms:viaservice",
    "aws:principalservicename", "lambda:functionurlauthtype", "sns:endpoint",
    "s3:dataaccesspointaccount", "s3:dataaccesspointarn",
}


def _list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def statements(doc: Any) -> Iterator[dict]:
    if not isinstance(doc, dict):
        return
    for s in _list(doc.get("Statement")):
        if isinstance(s, dict):
            yield s


def allows(stmt: dict) -> bool:
    return stmt.get("Effect") == "Allow"


def action_match(stmt: dict, action: str) -> bool:
    """True if the statement's Action covers `action` (case-insensitive, wildcards)."""
    action = action.lower()
    if "NotAction" in stmt:
        return not any(fnmatchcase(action, a.lower()) for a in _list(stmt["NotAction"]))
    return any(fnmatchcase(action, a.lower()) for a in _list(stmt.get("Action")))


def any_resource(stmt: dict) -> bool:
    if "NotResource" in stmt:
        return True
    return "*" in _list(stmt.get("Resource"))


def is_admin(doc: Any) -> bool:
    """Allow * on *, written either as Action:* or as a NotAction that excludes little."""
    for s in statements(doc):
        if allows(s) and any_resource(s) and "Action" in s and \
                any(a in ("*", "*:*") for a in _list(s["Action"])):
            return True
    return False


def grants(doc: Any, action: str, on_any_resource: bool = True) -> bool:
    for s in statements(doc):
        if allows(s) and action_match(s, action) and (any_resource(s) or not on_any_resource):
            return True
    return False


def _principal_values(principal: Any) -> list[str]:
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        out = []
        for v in principal.values():
            out += [str(x) for x in _list(v)]
        return out
    return [str(p) for p in _list(principal)]


def condition_keys(stmt: dict) -> set[str]:
    keys = set()
    for _, block in (stmt.get("Condition") or {}).items():
        if isinstance(block, dict):
            keys |= {k.lower() for k in block}
    return keys


def public_statements(doc: Any) -> list[dict]:
    """Allow statements open to any principal with no condition that narrows them."""
    out = []
    for s in statements(doc):
        if not allows(s):
            continue
        if "*" not in _principal_values(s.get("Principal")):
            continue
        if condition_keys(s) & RESTRICTING_KEYS:
            continue
        out.append(s)
    return out


def foreign_principals(doc: Any, own_account: str, known: set[str] = frozenset()) -> set[str]:
    """Account IDs, other than our own and other scanned accounts, granted access."""
    out = set()
    for s in statements(doc):
        if not allows(s):
            continue
        for p in _principal_values(s.get("Principal")):
            acct = p.split(":")[4] if p.startswith("arn:") and len(p.split(":")) > 4 else p
            if acct.isdigit() and len(acct) == 12 and acct != own_account and acct not in known:
                out.add(acct)
    return out


def summarize(stmt: dict) -> str:
    actions = _list(stmt.get("Action") or stmt.get("NotAction"))
    return f"Allow {', '.join(map(str, actions[:4]))}{'…' if len(actions) > 4 else ''} to " \
           f"{stmt.get('Principal')!s}"[:300]
