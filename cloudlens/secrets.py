"""Detect secret-looking values in environment variables, without keeping them.

Lambda and ECS environment variables come back in plain describe output. They are
scanned in memory here, and only the variable *name* and the *kind* of match survive;
every value is replaced before the resource is stored. Nothing secret reaches the
database, the UI, an export or a log line.
"""
from __future__ import annotations

import math
import re
from collections import Counter

REDACTED = "<redacted>"

_VALUE_PATTERNS = [
    ("aws-access-key-id", re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("stripe-live-key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("connection-string-password", re.compile(r"://[^/\s:@]+:[^/\s@]{3,}@")),
]

_SENSITIVE_NAME = re.compile(
    r"(PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH_?KEY|ACCESS_?KEY)",
    re.IGNORECASE,
)

# Values that point at a secret store rather than containing the secret.
_REFERENCE = re.compile(
    r"^(arn:aws[a-z-]*:(secretsmanager|ssm|kms):|\{\{resolve:|ssm:|/|\$\{)", re.IGNORECASE)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def classify(name: str, value: str) -> str:
    """Return the kind of secret this looks like, or '' if it does not."""
    value = value or ""
    for kind, pattern in _VALUE_PATTERNS:
        if pattern.search(value):
            return kind
    if _REFERENCE.match(value) or value.lower() in {"", "true", "false", "none", "null", "changeme"}:
        return ""
    if _SENSITIVE_NAME.search(name) and len(value) >= 8:
        return "sensitive-name"
    if len(value) >= 24 and " " not in value and _entropy(value) >= 4.2:
        return "high-entropy"
    return ""


def scrub_env(variables: dict | None) -> tuple[dict, list[dict]]:
    """Return (variables with every value redacted, [{name, kind}] for secret-looking ones)."""
    if not variables:
        return {}, []
    hits = []
    for name, value in variables.items():
        kind = classify(name, str(value))
        if kind:
            hits.append({"name": name, "kind": kind})
    return {name: REDACTED for name in variables}, hits
