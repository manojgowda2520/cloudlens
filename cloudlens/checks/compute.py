"""Lambda and container checks."""
from __future__ import annotations

from datetime import date
from typing import Iterator

from . import policy
from .base import Hit, View, check
from .identity import admin_source, documents, role_by_arn

# Lambda runtime deprecation dates (block-function-create phase starts later; this is
# the date AWS stops applying security patches). Source: AWS Lambda runtimes page.
RUNTIME_DEPRECATION = {
    "python2.7": date(2021, 7, 15), "python3.6": date(2022, 7, 18), "python3.7": date(2023, 12, 4),
    "python3.8": date(2024, 10, 14), "python3.9": date(2025, 12, 15), "python3.10": date(2026, 6, 30),
    "nodejs10.x": date(2021, 7, 30), "nodejs12.x": date(2023, 3, 31), "nodejs14.x": date(2023, 12, 4),
    "nodejs16.x": date(2024, 6, 12), "nodejs18.x": date(2025, 9, 1), "nodejs20.x": date(2026, 4, 30),
    "dotnetcore3.1": date(2023, 4, 3), "dotnet6": date(2024, 12, 20), "dotnet8": date(2026, 11, 10),
    "ruby2.5": date(2021, 7, 30), "ruby2.7": date(2023, 12, 7), "ruby3.2": date(2026, 3, 31),
    "java8": date(2024, 1, 8), "go1.x": date(2024, 1, 8), "provided": date(2024, 1, 8),
}

DANGEROUS = ("iam:PassRole", "iam:CreateAccessKey", "iam:AttachRolePolicy", "iam:PutRolePolicy",
             "iam:CreateUser", "sts:AssumeRole")


def _role(view: View, fn: dict):
    arn = fn["raw"].get("Role")
    return role_by_arn(view, arn) if arn else None


@check("LMB-01", "Critical", "Lambda execution role has administrator access",
       "Give the function its own role with only the actions and resources its code uses.")
def lambda_admin(view: View) -> Iterator[Hit]:
    for fn in view.of("lambda", "function"):
        role = _role(view, fn)
        if role:
            why = admin_source(view, role)
            if why:
                yield Hit(fn, f"role {role['name']}: {why}")


@check("LMB-02", "High", "Lambda role can escalate privileges",
       "Remove IAM-write and sts:AssumeRole on Resource:* from the function's role, or scope them to specific ARNs.")
def lambda_escalation(view: View) -> Iterator[Hit]:
    for fn in view.of("lambda", "function"):
        role = _role(view, fn)
        if not role or admin_source(view, role):
            continue   # already reported as LMB-01
        for label, doc in documents(view, role):
            found = [a for a in DANGEROUS if policy.grants(doc, a)]
            if found:
                yield Hit(fn, f"role {role['name']} {label} allows {', '.join(found)} on Resource:*")
                break


@check("LMB-03", "High", "Lambda function can be invoked by anyone",
       "Add a SourceArn/SourceAccount condition to the permission, or name the specific principal.")
def lambda_public_policy(view: View) -> Iterator[Hit]:
    for fn in view.of("lambda", "function"):
        for s in policy.public_statements(fn["raw"].get("Policy")):
            yield Hit(fn, f"resource policy statement {s.get('Sid', '')}: {policy.summarize(s)}")
            break


@check("LMB-04", "High", "Lambda function URL has no authentication",
       "Set the function URL AuthType to AWS_IAM, or put it behind API Gateway/CloudFront with auth.")
def lambda_open_url(view: View) -> Iterator[Hit]:
    for fn in view.of("lambda", "function"):
        for u in fn["raw"].get("UrlConfigs") or []:
            if u.get("AuthType") == "NONE":
                yield Hit(fn, f"{u.get('FunctionUrl')} AuthType = NONE")


@check("LMB-05", "High", "Lambda environment variable looks like a secret",
       "Move the value to Secrets Manager or SSM Parameter Store and read it at runtime.")
def lambda_env_secrets(view: View) -> Iterator[Hit]:
    for fn in view.of("lambda", "function"):
        hits = fn["raw"].get("SecretHits") or []
        if hits:
            yield Hit(fn, "; ".join(f"{h['name']} ({h['kind']})" for h in hits[:10]))


@check("LMB-06", "Medium", "Lambda runtime is deprecated",
       "Upgrade to a supported runtime; deprecated runtimes get no security patches.")
def lambda_runtime(view: View) -> Iterator[Hit]:
    today = view.now.date()
    for fn in view.of("lambda", "function"):
        rt = fn["raw"].get("Runtime")
        dep = RUNTIME_DEPRECATION.get(rt or "")
        if not dep:
            continue
        days = (dep - today).days
        if days <= 0:
            yield Hit(fn, f"runtime {rt} deprecated on {dep.isoformat()}")
        elif days <= 180:
            yield Hit(fn, f"runtime {rt} will be deprecated on {dep.isoformat()} ({days} days)", severity="Low")


@check("LMB-07", "Low", "Lambda environment not encrypted with a customer KMS key",
       "Set KMSKeyArn on the function if its environment holds anything sensitive.")
def lambda_env_kms(view: View) -> Iterator[Hit]:
    for fn in view.of("lambda", "function"):
        if (fn["raw"].get("Environment") or {}).get("Variables") and not fn["raw"].get("KMSKeyArn"):
            yield Hit(fn, f"{len(fn['raw']['Environment']['Variables'])} environment variables, KMSKeyArn not set")


@check("LMB-09", "Info", "Lambda function not invoked in 90 days",
       "Delete it if nothing needs it - every idle function is code and permissions nobody watches.")
def lambda_idle(view: View) -> Iterator[Hit]:
    for fn in view.of("lambda", "function"):
        if fn["raw"].get("Invocations90d") == 0:
            yield Hit(fn, "0 invocations in the last 90 days")


@check("ECS-01", "High", "ECS task definition environment variable looks like a secret",
       "Use the task definition 'secrets' field (Secrets Manager / SSM) instead of plain environment values.")
def ecs_env_secrets(view: View) -> Iterator[Hit]:
    for td in view.of("ecs", "task-definition"):
        hits = td["raw"].get("SecretHits") or []
        if hits:
            yield Hit(td, "; ".join(f"{h.get('container')}: {h['name']} ({h['kind']})" for h in hits[:10]))


@check("ECS-02", "High", "ECS container runs privileged",
       "Remove 'privileged: true'; grant only the specific Linux capabilities the container needs.")
def ecs_privileged(view: View) -> Iterator[Hit]:
    for td in view.of("ecs", "task-definition"):
        priv = [c.get("name") for c in td["raw"].get("containerDefinitions") or [] if c.get("privileged")]
        if priv:
            yield Hit(td, f"privileged containers: {', '.join(priv)}")
