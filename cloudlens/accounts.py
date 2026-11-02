"""Cross-account session management.

One collector process, N member accounts. Each account is reached by assuming a
read-only role; credentials are cached until 5 minutes before expiry and refreshed
lazily, so a long-running collector never wedges on an expired token.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config as BotoConfig

from .config import AccountConfig

log = logging.getLogger(__name__)

# Retries matter here: CloudWatch GetMetricData and the Pricing API both throttle
# aggressively once you are polling dozens of accounts.
BOTO_CONFIG = BotoConfig(
    retries={"max_attempts": 8, "mode": "adaptive"},
    connect_timeout=5,
    read_timeout=30,
    user_agent_extra="cloudlens/0.1",
)

_SKEW = timedelta(minutes=5)

# How long to wait before retrying identity resolution for an unreachable account.
_ID_RETRY_BACKOFF = timedelta(minutes=1)


class AccountSession:
    """Lazily-refreshing boto3 session for one account, plus a per-region client cache."""

    def __init__(self, cfg: AccountConfig, session_name: str = "cloudlens"):
        self.cfg = cfg
        self.session_name = session_name
        self._lock = threading.Lock()
        self._session: boto3.Session | None = None
        self._expires: datetime | None = None
        self._clients: dict[tuple[str, str], object] = {}
        self._resolved_id: str | None = None if cfg.account_id == "self" else cfg.account_id
        self._retry_id_after = datetime.min.replace(tzinfo=timezone.utc)

    @property
    def account_id(self) -> str:
        if self._resolved_id is None:
            self.session()  # resolves as a side effect
        return self._resolved_id or "unknown"

    def healthy(self) -> bool:
        """True if this account is actually reachable.

        Every estimator calls into AWS through `safe()`, which swallows failures and
        returns an empty result - so a broken role looks exactly like an account with
        no resources, and a collector that has gone blind reports $0 rather than an
        error. Checking identity once per pass distinguishes the two, which is what
        makes the CollectorStalled alert meaningful.
        """
        try:
            self.session()
        except Exception as exc:  # noqa: BLE001
            log.warning("%s unreachable: %s", self.cfg.name, exc)
            return False
        return self._resolved_id is not None

    @property
    def name(self) -> str:
        return self.cfg.name if self.cfg.name != "self" else self.account_id

    def session(self) -> boto3.Session:
        with self._lock:
            now = datetime.now(timezone.utc)
            fresh = self._session is not None and (
                self._expires is None or self._expires - _SKEW > now
            )
            if not fresh:
                self._session = self._build_session()
                self._clients.clear()
            if self._resolved_id is None and now >= self._retry_id_after:
                try:
                    self._resolved_id = self._session.client(
                        "sts", config=BOTO_CONFIG
                    ).get_caller_identity()["Account"]
                except Exception as exc:  # noqa: BLE001
                    # Missing credentials raise NoCredentialsError, not ClientError.
                    # Either way the collector should degrade, not die - but it must
                    # also not retry per task, or a broken account turns into an STS
                    # call storm across every estimator in every region.
                    self._retry_id_after = now + _ID_RETRY_BACKOFF
                    log.warning("could not resolve account id for %s: %s",
                                self.cfg.name, exc)
            return self._session

    def _build_session(self) -> boto3.Session:
        if not self.cfg.role_arn:
            self._expires = None
            return boto3.Session()

        sts = boto3.Session().client("sts", config=BOTO_CONFIG)
        kwargs = {
            "RoleArn": self.cfg.role_arn,
            "RoleSessionName": self.session_name,
            "DurationSeconds": 3600,
        }
        if self.cfg.external_id:
            kwargs["ExternalId"] = self.cfg.external_id
        creds = sts.assume_role(**kwargs)["Credentials"]
        self._expires = creds["Expiration"]
        log.info("assumed %s (expires %s)", self.cfg.role_arn, self._expires)
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    def client(self, service: str, region: str | None = None):
        key = (service, region or "-")
        self.session()  # ensure freshness before handing out a cached client
        with self._lock:
            if key not in self._clients:
                self._clients[key] = self._session.client(
                    service, region_name=region, config=BOTO_CONFIG
                )
            return self._clients[key]


def build_sessions(accounts: list[AccountConfig]) -> list[AccountSession]:
    return [AccountSession(a) for a in accounts]
