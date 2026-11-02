"""YAML config loading with sane defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import paths


@dataclass
class AccountConfig:
    account_id: str
    name: str
    role_arn: str | None = None      # None => use the collector's own credentials
    external_id: str | None = None
    regions: list[str] = field(default_factory=list)   # empty => inherit global


@dataclass
class Config:
    accounts: list[AccountConfig]
    regions: list[str]
    estimators: list[str]                 # [] or ["*"] => all registered
    disabled_estimators: list[str] = field(default_factory=list)
    scrape_interval: int = 60             # seconds, realtime estimators
    inventory_interval: int = 300         # seconds, describe/list estimators
    billing_interval: int = 3600          # seconds, Cost Explorer
    top_n: int = 200                      # per service+account+region cardinality cap
    min_usd_per_hour: float = 0.0         # drop noise below this rate
    tag_keys: list[str] = field(default_factory=list)   # promoted to metric labels
    pricing_cache_ttl: int = 86400
    pricing_cache_dir: str = field(default_factory=lambda: str(paths.pricing_cache()))
    port: int = 9101
    log_level: str = "INFO"
    ce_enabled: bool = True
    max_workers: int = 8

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        raw = yaml.safe_load(Path(path).read_text()) or {}
        raw = _expand_env(raw)

        regions = raw.get("regions") or ["us-east-1"]
        accounts = [
            AccountConfig(
                account_id=str(a["account_id"]),
                name=a.get("name") or str(a["account_id"]),
                role_arn=a.get("role_arn"),
                external_id=a.get("external_id"),
                regions=a.get("regions") or [],
            )
            for a in (raw.get("accounts") or [])
        ]
        if not accounts:
            # Single-account mode: use ambient credentials, discover the id at runtime.
            accounts = [AccountConfig(account_id="self", name="self")]

        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        kwargs = {k: v for k, v in raw.items() if k in known and k not in {"accounts", "regions"}}
        return cls(accounts=accounts, regions=regions, **kwargs)

    def regions_for(self, account: AccountConfig) -> list[str]:
        return account.regions or self.regions


def _expand_env(obj):
    """Expand ${VAR} in any string value, so secrets stay out of the YAML."""
    if isinstance(obj, dict):
        return {k: _expand_env(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_env(v) for v in obj]
    if isinstance(obj, str):
        return os.path.expandvars(obj)
    return obj
