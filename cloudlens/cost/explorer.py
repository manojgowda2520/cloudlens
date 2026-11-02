"""Daily spend per account and service from Cost Explorer, plus a month-end forecast.

Each Cost Explorer request costs $0.01, so results are cached for a day: a nightly
scan of six accounts is about $0.06 a month per call type. Queries are filtered to the
account itself, because in an Organization's management account Cost Explorer would
otherwise return the whole organisation's spend.
"""
from __future__ import annotations

import logging
from datetime import date, timedelta
from typing import Optional

from ..accounts import AccountSession

log = logging.getLogger(__name__)

CACHE_SECONDS = 24 * 3600


def _month_start(d: date) -> date:
    return d.replace(day=1)


def _next_month(d: date) -> date:
    return (d.replace(day=28) + timedelta(days=4)).replace(day=1)


def fetch(session: AccountSession, today: Optional[date] = None) -> tuple[list[tuple[str, str, float]], Optional[float]]:
    """Return ([(day, service, usd)] since the start of last month, full-month forecast)."""
    today = today or date.today()
    ce = session.client("ce", "us-east-1")
    account = session.account_id
    start = _month_start(_month_start(today) - timedelta(days=1))
    flt = {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [account]}}

    daily: list[tuple[str, str, float]] = []
    token = None
    while True:
        kw = dict(TimePeriod={"Start": start.isoformat(), "End": (today + timedelta(days=1)).isoformat()},
                  Granularity="DAILY", Metrics=["UnblendedCost"], Filter=flt,
                  GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}])
        if token:
            kw["NextPageToken"] = token
        resp = ce.get_cost_and_usage(**kw)
        for period in resp["ResultsByTime"]:
            day = period["TimePeriod"]["Start"]
            for g in period.get("Groups") or []:
                usd = float(g["Metrics"]["UnblendedCost"]["Amount"])
                if abs(usd) >= 0.0001:
                    daily.append((day, g["Keys"][0], usd))
        token = resp.get("NextPageToken")
        if not token:
            break

    forecast = None
    month_end = _next_month(today)
    if today + timedelta(days=1) < month_end:
        try:
            resp = ce.get_cost_forecast(
                TimePeriod={"Start": (today + timedelta(days=1)).isoformat(), "End": month_end.isoformat()},
                Metric="UNBLENDED_COST", Granularity="MONTHLY", Filter=flt)
            mtd = sum(usd for d, _, usd in daily if d >= _month_start(today).isoformat())
            forecast = mtd + float(resp["Total"]["Amount"])
        except Exception as exc:  # noqa: BLE001 - new accounts have too little history to forecast
            log.info("no forecast for %s: %s", account, exc)
    return daily, forecast
