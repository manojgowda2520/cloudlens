"""AWS Pricing API client with a disk-backed cache.

The Pricing API is slow, heavily throttled, and only available in a few regions, but
its data is essentially static - so every lookup is memoised in memory and on disk.
A cold start on a broad account does a few hundred lookups; every start after that
does none until the TTL lapses.

Everything returned is *public on-demand list price*. Savings Plans, Reserved
Instances, EDP/PPA discounts and credits are invisible here by construction - which is
exactly why `reconcile.py` exists to measure the gap against Cost Explorer.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from ..accounts import BOTO_CONFIG

log = logging.getLogger(__name__)

PRICING_REGION = "us-east-1"

# The Pricing API predates regionCode on some price lists and still keys on the
# human-readable location string. We filter on regionCode first and fall back to this.
REGION_TO_LOCATION = {
    "us-east-1": "US East (N. Virginia)", "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)", "us-west-2": "US West (Oregon)",
    "af-south-1": "Africa (Cape Town)", "ap-east-1": "Asia Pacific (Hong Kong)",
    "ap-south-1": "Asia Pacific (Mumbai)", "ap-south-2": "Asia Pacific (Hyderabad)",
    "ap-southeast-1": "Asia Pacific (Singapore)", "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-southeast-3": "Asia Pacific (Jakarta)", "ap-southeast-4": "Asia Pacific (Melbourne)",
    "ap-northeast-1": "Asia Pacific (Tokyo)", "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-northeast-3": "Asia Pacific (Osaka)", "ca-central-1": "Canada (Central)",
    "eu-central-1": "EU (Frankfurt)", "eu-central-2": "EU (Zurich)",
    "eu-west-1": "EU (Ireland)", "eu-west-2": "EU (London)", "eu-west-3": "EU (Paris)",
    "eu-north-1": "EU (Stockholm)", "eu-south-1": "EU (Milan)", "eu-south-2": "EU (Spain)",
    "il-central-1": "Israel (Tel Aviv)", "me-south-1": "Middle East (Bahrain)",
    "me-central-1": "Middle East (UAE)", "sa-east-1": "South America (Sao Paulo)",
}

HOURS_PER_MONTH = 730.0


class PricingClient:
    def __init__(self, session: boto3.Session, cache_dir: str, ttl: int = 86400):
        self._client = session.client("pricing", region_name=PRICING_REGION, config=BOTO_CONFIG)
        self._dir = Path(cache_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._ttl = ttl
        self._mem: dict[str, float | None] = {}
        self._lock = threading.Lock()
        self.lookups = 0
        self.cache_hits = 0

    # ---------------------------------------------------------------- public

    def price(
        self,
        service_code: str,
        filters: dict[str, str],
        *,
        region: str | None = None,
        unit_hint: str | None = None,
    ) -> float | None:
        """Return USD per unit for the cheapest matching on-demand price dimension.

        ``unit_hint`` disambiguates price lists that publish several dimensions for one
        product (e.g. Lambda's "Request" vs "Second"); it matches against the dimension
        unit, case-insensitively.
        """
        key = self._key(service_code, filters, region, unit_hint)
        with self._lock:
            if key in self._mem:
                self.cache_hits += 1
                return self._mem[key]

        cached = self._read_disk(key)
        if cached is not None:
            value = cached["value"]
            with self._lock:
                self._mem[key] = value
            self.cache_hits += 1
            return value

        value = self._fetch(service_code, filters, region, unit_hint)
        self._write_disk(key, value)
        with self._lock:
            self._mem[key] = value
        return value

    def hourly_from_monthly(self, monthly: float | None) -> float | None:
        return None if monthly is None else monthly / HOURS_PER_MONTH

    # --------------------------------------------------------------- internal

    def _fetch(self, service_code, filters, region, unit_hint) -> float | None:
        attempts: list[dict[str, str]] = []
        if region:
            attempts.append({**filters, "regionCode": region})
            loc = REGION_TO_LOCATION.get(region)
            if loc:
                attempts.append({**filters, "location": loc})
        else:
            attempts.append(dict(filters))

        for attempt in attempts:
            try:
                self.lookups += 1
                resp = self._client.get_products(
                    ServiceCode=service_code,
                    Filters=[
                        {"Type": "TERM_MATCH", "Field": k, "Value": str(v)}
                        for k, v in attempt.items()
                    ],
                    MaxResults=100,
                )
            except ClientError as exc:
                log.debug("pricing %s %s failed: %s", service_code, attempt, exc)
                continue

            best = self._cheapest(resp.get("PriceList", []), unit_hint)
            if best is not None:
                return best

        log.debug("no price for %s %s region=%s", service_code, filters, region)
        return None

    @staticmethod
    def _cheapest(price_list: list[str], unit_hint: str | None) -> float | None:
        """Pick the lowest non-zero USD rate across all matching dimensions.

        Products routinely carry a $0.00 free-tier dimension alongside the real one;
        taking the minimum of the *non-zero* rates is what matches the actual bill.
        """
        best: float | None = None
        for entry in price_list:
            doc = json.loads(entry) if isinstance(entry, str) else entry
            for term in doc.get("terms", {}).get("OnDemand", {}).values():
                for dim in term.get("priceDimensions", {}).values():
                    if unit_hint and unit_hint.lower() not in dim.get("unit", "").lower():
                        continue
                    try:
                        usd = float(dim.get("pricePerUnit", {}).get("USD", "0"))
                    except (TypeError, ValueError):
                        continue
                    if usd > 0 and (best is None or usd < best):
                        best = usd
        return best

    def _key(self, service_code, filters, region, unit_hint) -> str:
        blob = json.dumps(
            [service_code, sorted(filters.items()), region, unit_hint], sort_keys=True
        )
        return hashlib.sha256(blob.encode()).hexdigest()[:32]

    def _read_disk(self, key: str) -> dict | None:
        path = self._dir / f"{key}.json"
        if not path.exists():
            return None
        try:
            doc = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return None
        if time.time() - doc.get("ts", 0) > self._ttl:
            return None
        return doc

    def _write_disk(self, key: str, value: float | None) -> None:
        try:
            (self._dir / f"{key}.json").write_text(
                json.dumps({"ts": time.time(), "value": value})
            )
        except OSError as exc:
            log.debug("pricing cache write failed: %s", exc)
