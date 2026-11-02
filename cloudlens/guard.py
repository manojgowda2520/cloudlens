"""Read-only enforcement and audit logging for every AWS call cloudlens makes.

The SSO roles cloudlens runs under are often AdministratorAccess, and SSO offers no way
to attach a session policy that narrows them. So "read-only" cannot be left to IAM - it
is enforced here, in-process, before a request is signed:

1. The operation name must look like a read (Describe*, List*, Get*, ...) or be on a
   short, reviewed list of exceptions.
2. Even among reads, anything that returns customer *data* rather than *configuration*
   is refused: S3 objects, secret values, table items, log events, instance passwords.
   cloudlens inspects how things are set up, never what they contain.

Every call - allowed, blocked or failed - is recorded to the audit log, so "did this
tool change anything?" is answered by a query, not by trust.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional

import boto3

log = logging.getLogger(__name__)

READ_PREFIXES = ("Describe", "List", "Get", "BatchGet", "Lookup", "Search")

# Operations that do not start with a read verb but are needed and change nothing in
# the account. Each one is here for a stated reason.
EXTRA_ALLOWED = {
    # IAM builds the credential report asynchronously; generating it only refreshes a
    # cached CSV that GetCredentialReport then reads. No IAM entity is modified.
    ("iam", "GenerateCredentialReport"),
    # Cross-account access for accounts configured with an STS role instead of SSO.
    # It returns temporary credentials for the configured reader role; those sessions
    # are guarded too.
    ("sts", "AssumeRole"),
}

# SSO sign-in itself. These talk to the identity service, not to any account.
ALLOWED_SERVICES = {"sso-oidc"}

# Reads that return data rather than configuration, or mint credentials.
DENIED = {
    ("s3", "GetObject"), ("s3", "GetObjectAcl"), ("s3", "GetObjectAttributes"),
    ("s3", "GetObjectTorrent"), ("s3", "GetObjectTagging"), ("s3", "GetObjectRetention"),
    ("s3", "GetObjectLegalHold"),
    ("secretsmanager", "GetSecretValue"), ("secretsmanager", "BatchGetSecretValue"),
    ("ssm", "GetParameter"), ("ssm", "GetParameters"), ("ssm", "GetParametersByPath"),
    ("ssm", "GetParameterHistory"), ("ssm", "GetCommandInvocation"),
    ("lambda", "GetFunction"),          # returns a presigned URL to the code package
    ("lambda", "GetLayerVersion"),      # same, for layer content
    ("lambda", "GetLayerVersionByArn"),
    ("dynamodb", "GetItem"), ("dynamodb", "BatchGetItem"),
    ("logs", "GetLogEvents"), ("logs", "GetQueryResults"), ("logs", "GetLogRecord"),
    ("ec2", "GetPasswordData"), ("ec2", "GetConsoleOutput"), ("ec2", "GetConsoleScreenshot"),
    ("ecr", "GetAuthorizationToken"), ("ecr", "GetDownloadUrlForLayer"),
    ("ecr", "BatchGetImage"),
    ("kinesis", "GetRecords"), ("kinesis", "GetShardIterator"),
    ("athena", "GetQueryResults"),
    ("codecommit", "GetBlob"), ("codecommit", "GetFile"), ("codecommit", "GetFolder"),
    ("sts", "GetSessionToken"), ("sts", "GetFederationToken"),
    ("cognito-identity", "GetCredentialsForIdentity"), ("cognito-identity", "GetOpenIdToken"),
    ("redshift", "GetClusterCredentials"), ("redshift", "GetClusterCredentialsWithIAM"),
    ("rds", "GenerateDbAuthToken"),
    ("glacier", "GetJobOutput"),
}


class WriteBlocked(PermissionError):
    """Raised before signing when an AWS call is not a permitted read."""


def is_allowed(service: str, operation: str) -> bool:
    if service in ALLOWED_SERVICES:
        return True
    if (service, operation) in DENIED:
        return False
    if (service, operation) in EXTRA_ALLOWED:
        return True
    return operation.startswith(READ_PREFIXES)


class AuditLog:
    """Thread-safe buffer of API call records, flushed to a sink in batches.

    The sink is the store's `record_api_calls`. Buffering keeps a scan of thousands of
    calls from turning into thousands of SQLite transactions.
    """

    def __init__(self, sink: Optional[Callable[[list[tuple]], None]] = None, batch: int = 200):
        self._sink = sink
        self._batch = batch
        self._rows: list[tuple] = []
        self._lock = threading.Lock()
        self.blocked = 0

    def record(self, portal: str, account: str, region: str, service: str,
               operation: str, outcome: str, error: str = "") -> None:
        row = (time.time(), portal, account, region, service, operation, outcome, error[:500])
        with self._lock:
            self._rows.append(row)
            if outcome == "blocked":
                self.blocked += 1
            full = len(self._rows) >= self._batch
        if full:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            rows, self._rows = self._rows, []
        if rows and self._sink is not None:
            try:
                self._sink(rows)
            except Exception:  # noqa: BLE001 - auditing must not break a scan
                log.exception("could not write %d audit rows", len(rows))


def protect(session: boto3.Session, *, account: str = "", portal: str = "",
            audit: Optional[AuditLog] = None) -> boto3.Session:
    """Install the read-only guard (and audit hooks) on a boto3 session.

    Hooks are registered on the session's event system, which every client created
    from it inherits, so it covers clients made before or after this call.
    """
    events = session.events
    if getattr(session, "_cloudlens_protected", False):
        return session

    def _service(model) -> str:
        return model.service_model.service_name

    def before_call(model, context, request_signer=None, **_):
        service, op = _service(model), model.name
        region = getattr(request_signer, "region_name", "") or ""
        context["cloudlens_region"] = region
        context["cloudlens_op"] = (service, op)   # after-call-error is not given the model
        if not is_allowed(service, op):
            if audit is not None:
                audit.record(portal, account, region, service, op, "blocked")
            log.error("blocked non-read AWS call %s:%s in %s", service, op, account or "?")
            raise WriteBlocked(f"cloudlens is read-only: refused {service}:{op}")

    def after_call(model, context, http_response=None, **_):
        if audit is None:
            return
        status = getattr(http_response, "status_code", 0)
        outcome = "ok" if status and status < 400 else f"http {status}"
        audit.record(portal, account, context.get("cloudlens_region", ""),
                     _service(model), model.name, outcome)

    def after_call_error(context=None, exception=None, **_):
        if audit is None or not context:
            return
        service, op = context.get("cloudlens_op", ("?", "?"))
        audit.record(portal, account, context.get("cloudlens_region", ""),
                     service, op, "error", str(exception))

    events.register("before-call", before_call, unique_id="cloudlens-guard")
    events.register("after-call", after_call, unique_id="cloudlens-audit")
    events.register("after-call-error", after_call_error, unique_id="cloudlens-audit-err")
    session._cloudlens_protected = True  # type: ignore[attr-defined]
    return session
