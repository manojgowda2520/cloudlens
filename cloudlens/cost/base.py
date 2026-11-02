"""Estimator plugin contract and registry."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator

from ..accounts import AccountSession
from .cloudwatch import MetricReader
from .models import ResourceCost, Tier
from .pricing import PricingClient

log = logging.getLogger(__name__)


@dataclass
class Context:
    """Everything an estimator is handed for one (account, region) pass."""

    session: AccountSession
    region: str
    pricing: PricingClient
    window: int = 300
    tag_keys: tuple[str, ...] = ()

    @property
    def account_id(self) -> str:
        return self.session.account_id

    @property
    def account_name(self) -> str:
        return self.session.name

    def client(self, service: str):
        return self.session.client(service, self.region)

    def metrics(self, window: int | None = None) -> MetricReader:
        return MetricReader(self.client("cloudwatch"), window_seconds=window or self.window)

    def cost(self, **kw) -> ResourceCost:
        kw.setdefault("account_id", self.account_id)
        kw.setdefault("account_name", self.account_name)
        kw.setdefault("region", self.region)
        return ResourceCost(**kw)

    def paginate(self, service: str, operation: str, key: str, **kwargs) -> Iterator[dict]:
        """Yield every item under ``key`` across all pages of ``operation``."""
        client = self.client(service)
        paginator = client.get_paginator(operation)
        for page in paginator.paginate(**kwargs):
            yield from page.get(key, [])


class Estimator:
    """Base class. Subclasses implement :meth:`collect` and set the class attributes."""

    name: str = ""
    tier: Tier = Tier.REALTIME
    cadence: str = "realtime"     # realtime | inventory | billing
    global_service: bool = False  # collect once per account, not once per region
    required_actions: tuple[str, ...] = ()   # documented in the generated IAM policy

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:  # pragma: no cover
        raise NotImplementedError


_REGISTRY: dict[str, type[Estimator]] = {}


def register(cls: type[Estimator]) -> type[Estimator]:
    if not cls.name:
        raise ValueError(f"{cls.__name__} must set a name")
    if cls.name in _REGISTRY:
        raise ValueError(f"duplicate estimator name {cls.name!r}")
    _REGISTRY[cls.name] = cls
    return cls


def registry() -> dict[str, type[Estimator]]:
    from . import estimators  # noqa: F401  (import triggers registration)

    return dict(_REGISTRY)


def select(enabled: list[str], disabled: list[str]) -> list[Estimator]:
    all_ = registry()
    if not enabled or "*" in enabled:
        chosen = list(all_)
    else:
        chosen = []
        for nm in enabled:
            if nm not in all_:
                log.warning("unknown estimator %r (have: %s)", nm, ", ".join(sorted(all_)))
                continue
            chosen.append(nm)
    return [all_[n]() for n in chosen if n not in set(disabled)]


def safe(fn: Callable, default, what: str):
    """Run an AWS call, log and swallow anything that goes wrong.

    One denied permission or one unsupported region must never take down the whole
    collection pass - partial cost data is far more useful than none.
    """
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - deliberately broad, this is the boundary
        log.warning("%s failed: %s", what, exc)
        return default
