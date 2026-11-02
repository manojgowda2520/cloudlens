"""Collector contract: one function per service area, run once per (account, region).

A collector yields `Resource`s. Raw describe output is kept on each resource (minus
anything secret) so security checks can read any field without a second API call, and
so checks added later can be re-run against old scans.

Failures are recorded on the context rather than raised: one denied call or one
service missing from a region must not cost the rest of the scan. But they are
*recorded*, so the UI can say "partial coverage" instead of showing a silent zero.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Iterator, Optional

from botocore.exceptions import ClientError, EndpointConnectionError

from ..accounts import AccountSession

log = logging.getLogger(__name__)


@dataclass
class Resource:
    arn: str
    account_id: str
    region: str           # "global" for IAM, S3 buckets, Route 53, CloudFront
    service: str
    type: str
    name: str
    raw: dict
    tags: dict = field(default_factory=dict)
    created: Optional[str] = None


# Errors that mean "this service is not here", not "something went wrong".
_ABSENT_CODES = {
    "UnrecognizedClientException", "InvalidClientTokenId", "OptInRequired",
    "SubscriptionRequiredException", "UnsupportedOperation", "InvalidAction",
    "AuthFailure",  # region not enabled for this account
}


def _absent(exc: Exception) -> bool:
    if isinstance(exc, EndpointConnectionError):
        return True
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        msg = exc.response.get("Error", {}).get("Message", "").lower()
        return code in _ABSENT_CODES or "not supported in" in msg or "not available in" in msg
    return False


class Ctx:
    """Everything a collector gets for one (account, region) pass."""

    def __init__(self, session: AccountSession, region: str, home_region: str = "us-east-1"):
        self.session = session
        self.region = region
        self.home_region = home_region
        self.errors: list[tuple[str, str, str, str]] = []   # (account, region, collector, message)
        self.collector = ""

    @property
    def account_id(self) -> str:
        return self.session.account_id

    @property
    def partition(self) -> str:
        r = self.region if self.region != "global" else self.home_region
        return "aws-cn" if r.startswith("cn-") else "aws-us-gov" if r.startswith("us-gov-") else "aws"

    def client(self, service: str, region: Optional[str] = None):
        r = region or (self.home_region if self.region == "global" else self.region)
        return self.session.client(service, r)

    def call(self, fn: Callable[[], Any], what: str, default: Any = None,
             quiet: Iterable[str] = ()) -> Any:
        """Run one AWS call; on failure record it and return `default`.

        `quiet` lists error codes that are an expected answer rather than a failure
        (e.g. NoSuchBucketPolicy - the bucket simply has no policy).
        """
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in set(quiet) or _absent(exc):
                return default
            self._error(what, f"{code}: {exc.response.get('Error', {}).get('Message', '')}")
        except Exception as exc:  # noqa: BLE001 - the scan boundary
            if _absent(exc):
                return default
            self._error(what, f"{type(exc).__name__}: {exc}")
        return default

    def pages(self, client, op: str, key: str, what: str = "", **kw) -> list:
        """All items from a paginated (or plain) list call, or [] on failure."""
        def run():
            if client.can_paginate(op):
                out = []
                for page in client.get_paginator(op).paginate(**kw):
                    out.extend(page.get(key) or [])
                return out
            return getattr(client, op)(**kw).get(key) or []
        return self.call(run, what or f"{client.meta.service_model.service_name}:{op}", [])

    def _error(self, what: str, message: str) -> None:
        log.debug("%s %s %s: %s", self.account_id, self.region, what, message)
        self.errors.append((self.account_id, self.region, f"{self.collector} {what}".strip(),
                            message[:500]))

    def arn(self, service: str, resource: str, region: Optional[str] = None,
            account: Optional[str] = None) -> str:
        r = self.region if region is None else region
        r = "" if r == "global" else r
        a = self.account_id if account is None else account
        return f"arn:{self.partition}:{service}:{r}:{a}:{resource}"

    def res(self, service: str, type_: str, arn: str, name: str, raw: dict,
            tags: Optional[dict] = None, created: Any = None, region: Optional[str] = None) -> Resource:
        return Resource(
            arn=arn, account_id=self.account_id, region=region or self.region,
            service=service, type=type_, name=name or arn.rsplit(":", 1)[-1], raw=raw,
            tags=tags if tags is not None else tags_of(raw.get("Tags") or raw.get("TagList") or raw.get("tags")),
            created=_iso(created),
        )


def _iso(value: Any) -> Optional[str]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat(timespec="seconds")
    if isinstance(value, (int, float)):
        secs = value / 1000 if value > 1e11 else value   # some APIs use epoch millis
        return datetime.fromtimestamp(secs, tz=timezone.utc).isoformat(timespec="seconds")
    return str(value)


def tags_of(tags: Any) -> dict:
    if not tags:
        return {}
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    out = {}
    for t in tags:
        k = t.get("Key") or t.get("key")
        if k is not None:
            out[str(k)] = str(t.get("Value") or t.get("value") or "")
    return out


# ------------------------------------------------------------------- registry

@dataclass
class Collector:
    name: str
    scope: str            # "regional" | "global"
    fn: Callable[[Ctx], Iterator[Resource]]


_REGISTRY: dict[str, Collector] = {}


def collector(name: str, scope: str = "regional"):
    def wrap(fn):
        _REGISTRY[name] = Collector(name, scope, fn)
        return fn
    return wrap


def collectors() -> dict[str, Collector]:
    from . import global_, regional  # noqa: F401 - registration side effect
    return dict(_REGISTRY)
