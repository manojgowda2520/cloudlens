"""Read models for the dashboard pages.

"Current" data is per account: each account's newest finished scan that covered it.
A scan limited to one account must not make every other account look empty.
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import date, timedelta
from typing import Optional

from ..checks.base import View
from ..cost import waste
from ..store import SEVERITIES, Store

_SUPPRESSED = ("EXISTS (SELECT 1 FROM suppressions s WHERE s.check_id=f.check_id"
               " AND (s.arn=f.arn OR s.arn='*'))")
_NOT_SUPPRESSED = "NOT " + _SUPPRESSED


def current_scans(store: Store) -> dict[str, int]:
    rows = store.q("SELECT r.account_id, MAX(r.scan_id) scan_id FROM resources r JOIN scans s "
                   "ON s.id=r.scan_id WHERE s.status IN ('ok','partial') GROUP BY r.account_id")
    return {r["account_id"]: r["scan_id"] for r in rows}


def previous_scans(store: Store, current: dict[str, int]) -> dict[str, int]:
    out = {}
    for acct, sid in current.items():
        row = store.one("SELECT MAX(r.scan_id) id FROM resources r JOIN scans s ON s.id=r.scan_id "
                        "WHERE r.account_id=? AND r.scan_id<? AND s.status IN ('ok','partial')", (acct, sid))
        if row and row["id"]:
            out[acct] = row["id"]
    return out


def _pairs(scans: dict[str, int], alias: str = "") -> tuple[str, list]:
    a = f"{alias}." if alias else ""
    if not scans:
        return "0", []
    clause = " OR ".join(f"({a}account_id=? AND {a}scan_id=?)" for _ in scans)
    args: list = []
    for acct, sid in scans.items():
        args += [acct, sid]
    return f"({clause})", args


def accounts_overview(store: Store) -> list[dict]:
    cur = current_scans(store)
    out = []
    month = date.today().replace(day=1).isoformat()
    for a in store.accounts():
        sid = cur.get(a["account_id"])
        sev = {s: 0 for s in SEVERITIES}
        resources = errors = 0
        scanned_at = None
        if sid:
            for r in store.q(f"SELECT severity, COUNT(*) n FROM findings f WHERE scan_id=? AND account_id=? "
                             f"AND {_NOT_SUPPRESSED} GROUP BY severity", (sid, a["account_id"])):
                sev[r["severity"]] = r["n"]
            resources = store.one("SELECT COUNT(*) n FROM resources WHERE scan_id=? AND account_id=?",
                                  (sid, a["account_id"]))["n"]
            errors = store.one("SELECT COUNT(*) n FROM scan_errors WHERE scan_id=? AND account_id=?",
                               (sid, a["account_id"]))["n"]
            scanned_at = store.scan(sid)["finished_at"]
        mtd = store.one("SELECT SUM(usd) v FROM cost_daily WHERE account_id=? AND day>=?",
                        (a["account_id"], month))["v"]
        meta = store.one("SELECT * FROM cost_meta WHERE account_id=?", (a["account_id"],))
        out.append({**dict(a), "scan_id": sid, "severity": sev, "resources": resources, "errors": errors,
                    "scanned_at": scanned_at, "mtd": mtd, "forecast": meta["forecast_usd"] if meta else None,
                    "cost_error": meta["error"] if meta else None})
    return out


def findings(store: Store, *, severity: Optional[str] = None, account: Optional[str] = None,
             check: Optional[str] = None, q: Optional[str] = None, suppressed: bool = False,
             new_only: bool = False, limit: int = 2000) -> list[dict]:
    cur = current_scans(store)
    if account:
        cur = {k: v for k, v in cur.items() if k == account}
    clause, args = _pairs(cur, "f")
    sql = f"SELECT f.*, a.name account_name FROM findings f LEFT JOIN accounts a ON a.account_id=f.account_id WHERE {clause}"
    if severity:
        sql += " AND f.severity=?"
        args.append(severity)
    if check:
        sql += " AND f.check_id=?"
        args.append(check)
    if q:
        sql += " AND (f.arn LIKE ? OR f.title LIKE ? OR f.evidence LIKE ?)"
        args += [f"%{q}%"] * 3
    sql += " AND " + (_SUPPRESSED if suppressed else _NOT_SUPPRESSED)
    rows = [dict(r) for r in store.q(sql + " LIMIT ?", args + [limit])]
    if new_only:
        prev = previous_scans(store, cur)
        old = set()
        if prev:
            pc, pa = _pairs(prev)
            old = {(r["check_id"], r["arn"]) for r in store.q(f"SELECT check_id, arn FROM findings WHERE {pc}", pa)}
        rows = [r for r in rows if r["account_id"] in prev and (r["check_id"], r["arn"]) not in old]
    order = {s: i for i, s in enumerate(SEVERITIES)}
    rows.sort(key=lambda r: (order.get(r["severity"], 9), r["check_id"], r["account_id"], r["arn"]))
    return rows


def severity_totals(rows: list[dict]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITIES}
    for r in rows:
        out[r["severity"]] = out.get(r["severity"], 0) + 1
    return out


def inventory(store: Store, *, account: Optional[str] = None, region: Optional[str] = None,
              service: Optional[str] = None, q: Optional[str] = None, limit: int = 500) -> tuple[list[dict], int]:
    cur = current_scans(store)
    if account:
        cur = {k: v for k, v in cur.items() if k == account}
    clause, args = _pairs(cur, "r")
    sql = f" FROM resources r LEFT JOIN accounts a ON a.account_id=r.account_id WHERE {clause}"
    if region:
        sql += " AND r.region=?"
        args.append(region)
    if service:
        sql += " AND r.service=?"
        args.append(service)
    if q:
        sql += " AND (r.name LIKE ? OR r.arn LIKE ? OR r.tags LIKE ? OR r.type LIKE ?)"
        args += [f"%{q}%"] * 4
    total = store.one("SELECT COUNT(*) n" + sql, args)["n"]
    rows = store.q("SELECT r.scan_id, r.arn, r.account_id, r.region, r.service, r.type, r.name, r.tags, r.created,"
                   " a.name account_name" + sql + " ORDER BY r.service, r.type, r.name LIMIT ?", args + [limit])
    out = []
    for r in rows:
        d = dict(r)
        d["tags"] = json.loads(d["tags"] or "{}")
        out.append(d)
    return out, total


def facets(store: Store) -> dict:
    cur = current_scans(store)
    clause, args = _pairs(cur)
    return {
        "regions": [r["region"] for r in store.q(f"SELECT DISTINCT region FROM resources WHERE {clause} ORDER BY region", args)],
        "services": [dict(r) for r in store.q(f"SELECT service, COUNT(*) n FROM resources WHERE {clause} "
                                              "GROUP BY service ORDER BY n DESC", args)],
    }


def resource(store: Store, arn: str) -> Optional[dict]:
    cur = current_scans(store)
    clause, args = _pairs(cur)
    row = store.one(f"SELECT * FROM resources WHERE arn=? AND {clause}", [arn] + args) or \
        store.one("SELECT * FROM resources WHERE arn=? ORDER BY scan_id DESC LIMIT 1", (arn,))
    if not row:
        return None
    d = dict(row)
    d["raw"] = json.loads(d["raw"] or "{}")
    d["tags"] = json.loads(d["tags"] or "{}")
    d["findings"] = [dict(f) for f in store.q("SELECT * FROM findings WHERE scan_id=? AND arn=?", (d["scan_id"], arn))]
    d["cost"] = store.q("SELECT * FROM resource_cost WHERE scan_id=? AND account_id=? AND ? LIKE '%' || resource_id",
                        (d["scan_id"], d["account_id"], arn))
    return d


def views(store: Store) -> list[View]:
    return [View.from_rows(acct, store.resources(sid, acct)) for acct, sid in current_scans(store).items()]


def cost_summary(store: Store) -> dict:
    today = date.today()
    month = today.replace(day=1)
    last_month = (month - timedelta(days=1)).replace(day=1)
    by_service = store.q("SELECT service, SUM(usd) v FROM cost_daily WHERE day>=? GROUP BY service "
                         "ORDER BY v DESC LIMIT 15", (month.isoformat(),))
    daily = store.q("SELECT day, SUM(usd) v FROM cost_daily WHERE day>=? GROUP BY day ORDER BY day",
                    ((today - timedelta(days=30)).isoformat(),))
    per_account = store.q(
        "SELECT a.account_id, a.name, "
        " (SELECT SUM(usd) FROM cost_daily c WHERE c.account_id=a.account_id AND c.day>=?) mtd, "
        " (SELECT SUM(usd) FROM cost_daily c WHERE c.account_id=a.account_id AND c.day>=? AND c.day<?) last, "
        " m.forecast_usd forecast, m.fetched_at, m.error "
        "FROM accounts a LEFT JOIN cost_meta m ON m.account_id=a.account_id WHERE a.enabled=1 ORDER BY mtd DESC",
        (month.isoformat(), last_month.isoformat(), month.isoformat()))
    cur = current_scans(store)
    clause, args = _pairs(cur)
    top = store.q(f"SELECT account_id, region, service, resource_id, SUM(usd_per_hour) h FROM resource_cost "
                  f"WHERE {clause} GROUP BY account_id, region, service, resource_id ORDER BY h DESC LIMIT 25", args)
    w = []
    for v in views(store):
        w += waste.find(v)
    w.sort(key=lambda x: -x.usd_month)
    return {
        "by_service": [dict(r) for r in by_service], "daily": [dict(r) for r in daily],
        "accounts": [dict(r) for r in per_account], "top": [dict(r) for r in top],
        "waste": w, "waste_total": waste.total(w),
        "mtd": sum((r["mtd"] or 0) for r in per_account),
        "forecast": sum((r["forecast"] or 0) for r in per_account),
        "last": sum((r["last"] or 0) for r in per_account),
    }


def diff(store: Store, a: int, b: int) -> dict:
    """What changed from scan `a` to scan `b`, over the accounts both scans covered."""
    accts = {r["account_id"] for r in store.q("SELECT DISTINCT account_id FROM resources WHERE scan_id=?", (a,))} & \
            {r["account_id"] for r in store.q("SELECT DISTINCT account_id FROM resources WHERE scan_id=?", (b,))}
    if not accts:
        return {"accounts": [], "added": [], "removed": [], "opened": [], "closed": []}
    marks = ",".join("?" * len(accts))

    def res(sid):
        return {r["arn"]: dict(r) for r in store.q(
            f"SELECT arn, account_id, region, service, type, name FROM resources WHERE scan_id=? AND account_id IN ({marks})",
            [sid, *accts])}

    def fnd(sid):
        return {(r["check_id"], r["arn"]): dict(r) for r in store.q(
            f"SELECT * FROM findings WHERE scan_id=? AND account_id IN ({marks})", [sid, *accts])}

    ra, rb, fa, fb = res(a), res(b), fnd(a), fnd(b)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    sort = lambda xs: sorted(xs, key=lambda f: (order.get(f["severity"], 9), f["check_id"]))  # noqa: E731
    return {
        "accounts": sorted(accts),
        "added": [rb[k] for k in sorted(rb.keys() - ra.keys())],
        "removed": [ra[k] for k in sorted(ra.keys() - rb.keys())],
        "opened": sort([fb[k] for k in fb.keys() - fa.keys()]),
        "closed": sort([fa[k] for k in fa.keys() - fb.keys()]),
    }


def by_service_counts(rows: list[dict]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for r in rows:
        out[r["service"]] += 1
    return dict(out)
