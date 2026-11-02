"""SQLite persistence: portals, accounts, scans, inventory, findings, cost, audit log.

One file (~/.cloudlens/cloudlens.db), WAL mode so the web UI can read while a scan
writes. Every write goes through a single lock: scans fan out across threads, and
SQLite allows one writer at a time anyway, so serialising here is simpler than
retrying on SQLITE_BUSY.

Inventory and findings are stored per scan, which is what makes "what changed since
last week" a set difference. Raw describe output is kept so new checks can be
re-run against old scans; old scans are pruned to bound disk use.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Optional

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS portals (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    start_url   TEXT NOT NULL UNIQUE,
    sso_region  TEXT NOT NULL,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    account_id  TEXT PRIMARY KEY,
    portal_id   TEXT NOT NULL REFERENCES portals(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    email       TEXT,
    role_name   TEXT,
    roles       TEXT,              -- JSON list of every role offered
    enabled     INTEGER NOT NULL DEFAULT 0,
    regions     TEXT,              -- JSON list; NULL = every enabled region
    added_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  REAL NOT NULL,
    finished_at REAL,
    status      TEXT NOT NULL,     -- running | ok | partial | failed
    modules     TEXT NOT NULL,
    accounts    INTEGER DEFAULT 0,
    resources   INTEGER DEFAULT 0,
    findings    INTEGER DEFAULT 0,
    errors      INTEGER DEFAULT 0,
    message     TEXT
);

CREATE TABLE IF NOT EXISTS scan_errors (
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    account_id  TEXT, region TEXT, collector TEXT, message TEXT
);

CREATE TABLE IF NOT EXISTS resources (
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    arn         TEXT NOT NULL,
    account_id  TEXT NOT NULL,
    region      TEXT NOT NULL,
    service     TEXT NOT NULL,
    type        TEXT NOT NULL,
    name        TEXT,
    tags        TEXT,
    created     TEXT,
    raw         TEXT,
    PRIMARY KEY (scan_id, arn)
);
CREATE INDEX IF NOT EXISTS resources_lookup ON resources(scan_id, account_id, service);

CREATE TABLE IF NOT EXISTS findings (
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id    TEXT NOT NULL,
    arn         TEXT NOT NULL,
    account_id  TEXT NOT NULL,
    region      TEXT,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    evidence    TEXT,
    remediation TEXT,
    source      TEXT NOT NULL DEFAULT 'cloudlens',
    PRIMARY KEY (scan_id, check_id, arn)
);
CREATE INDEX IF NOT EXISTS findings_lookup ON findings(scan_id, account_id, severity);

CREATE TABLE IF NOT EXISTS suppressions (
    check_id    TEXT NOT NULL,
    arn         TEXT NOT NULL,     -- '*' suppresses the check everywhere
    reason      TEXT NOT NULL,
    created_at  REAL NOT NULL,
    PRIMARY KEY (check_id, arn)
);

CREATE TABLE IF NOT EXISTS cost_daily (
    account_id  TEXT NOT NULL,
    day         TEXT NOT NULL,
    service     TEXT NOT NULL,
    usd         REAL NOT NULL,
    PRIMARY KEY (account_id, day, service)
);

CREATE TABLE IF NOT EXISTS cost_meta (
    account_id  TEXT PRIMARY KEY,
    fetched_at  REAL NOT NULL,
    forecast_usd REAL,             -- full current month, if Cost Explorer can forecast
    error       TEXT
);

CREATE TABLE IF NOT EXISTS resource_cost (
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    account_id  TEXT NOT NULL,
    region      TEXT NOT NULL,
    service     TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    usd_per_hour REAL NOT NULL,
    tier        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_calls (
    ts          REAL NOT NULL,
    portal_id   TEXT, account_id TEXT, region TEXT,
    service     TEXT NOT NULL,
    operation   TEXT NOT NULL,
    outcome     TEXT NOT NULL,     -- ok | http 4xx | error | blocked
    error       TEXT
);
CREATE INDEX IF NOT EXISTS api_calls_ts ON api_calls(ts);
"""

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


class Store:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(SCHEMA)
        self._db.execute("INSERT OR IGNORE INTO meta VALUES ('schema_version', ?)",
                         (str(SCHEMA_VERSION),))

    # ---------------------------------------------------------------- helpers

    def q(self, sql: str, args: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, tuple(args)).fetchall()

    def one(self, sql: str, args: Iterable[Any] = ()) -> Optional[sqlite3.Row]:
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args: Iterable[Any] = ()) -> int:
        with self._lock:
            return self._db.execute(sql, tuple(args)).lastrowid

    def many(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.executemany(sql, rows)
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ---------------------------------------------------------------- portals

    def add_portal(self, portal_id: str, name: str, start_url: str, sso_region: str) -> None:
        self.x("INSERT INTO portals VALUES (?,?,?,?,?)",
               (portal_id, name, start_url, sso_region, time.time()))

    def portals(self) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM portals ORDER BY name")

    def portal(self, portal_id: str) -> Optional[sqlite3.Row]:
        return self.one("SELECT * FROM portals WHERE id=?", (portal_id,))

    def delete_portal(self, portal_id: str) -> None:
        self.x("DELETE FROM portals WHERE id=?", (portal_id,))

    # --------------------------------------------------------------- accounts

    def upsert_discovered(self, portal_id: str, account_id: str, name: str,
                          email: str, roles: list[str]) -> bool:
        """Record an account seen through a portal. Returns False if another portal
        already owns it - the first portal to reach an account wins."""
        existing = self.one("SELECT portal_id FROM accounts WHERE account_id=?", (account_id,))
        if existing and existing["portal_id"] != portal_id:
            return False
        if existing:
            self.x("UPDATE accounts SET name=?, email=?, roles=? WHERE account_id=?",
                   (name, email, json.dumps(roles), account_id))
        else:
            self.x("INSERT INTO accounts (account_id, portal_id, name, email, role_name, roles,"
                   " enabled, regions, added_at) VALUES (?,?,?,?,?,?,0,NULL,?)",
                   (account_id, portal_id, name, email, pick_role(roles),
                    json.dumps(roles), time.time()))
        return True

    def accounts(self, enabled_only: bool = False, portal_id: Optional[str] = None) -> list[sqlite3.Row]:
        sql = ("SELECT a.*, p.name AS portal_name FROM accounts a "
               "JOIN portals p ON p.id = a.portal_id WHERE 1=1")
        args: list[Any] = []
        if enabled_only:
            sql += " AND a.enabled=1"
        if portal_id:
            sql += " AND a.portal_id=?"
            args.append(portal_id)
        return self.q(sql + " ORDER BY p.name, a.name", args)

    def account(self, account_id: str) -> Optional[sqlite3.Row]:
        return self.one("SELECT a.*, p.name AS portal_name FROM accounts a "
                        "JOIN portals p ON p.id=a.portal_id WHERE account_id=?", (account_id,))

    def set_account(self, account_id: str, *, enabled: Optional[bool] = None,
                    role_name: Optional[str] = None, regions: Optional[list[str]] = None,
                    clear_regions: bool = False) -> None:
        if enabled is not None:
            self.x("UPDATE accounts SET enabled=? WHERE account_id=?", (int(enabled), account_id))
        if role_name is not None:
            self.x("UPDATE accounts SET role_name=? WHERE account_id=?", (role_name, account_id))
        if regions is not None or clear_regions:
            value = json.dumps(regions) if regions else None
            self.x("UPDATE accounts SET regions=? WHERE account_id=?", (value, account_id))

    # ------------------------------------------------------------------ scans

    def start_scan(self, modules: list[str]) -> int:
        return self.x("INSERT INTO scans (started_at, status, modules) VALUES (?, 'running', ?)",
                      (time.time(), ",".join(modules)))

    def finish_scan(self, scan_id: int, status: str, message: str = "") -> None:
        counts = {
            "accounts": self.one("SELECT COUNT(DISTINCT account_id) n FROM resources WHERE scan_id=?",
                                 (scan_id,))["n"],
            "resources": self.one("SELECT COUNT(*) n FROM resources WHERE scan_id=?", (scan_id,))["n"],
            "findings": self.one("SELECT COUNT(*) n FROM findings WHERE scan_id=?", (scan_id,))["n"],
            "errors": self.one("SELECT COUNT(*) n FROM scan_errors WHERE scan_id=?", (scan_id,))["n"],
        }
        self.x("UPDATE scans SET finished_at=?, status=?, message=?, accounts=?, resources=?,"
               " findings=?, errors=? WHERE id=?",
               (time.time(), status, message, counts["accounts"], counts["resources"],
                counts["findings"], counts["errors"], scan_id))

    def scans(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))

    def scan(self, scan_id: int) -> Optional[sqlite3.Row]:
        return self.one("SELECT * FROM scans WHERE id=?", (scan_id,))

    def latest_scan_id(self) -> Optional[int]:
        row = self.one("SELECT id FROM scans WHERE status IN ('ok','partial') ORDER BY id DESC LIMIT 1")
        return row["id"] if row else None

    def latest_scan_for(self, account_id: str) -> Optional[int]:
        """The newest finished scan that covered this account (scans may be partial)."""
        row = self.one("SELECT MAX(r.scan_id) id FROM resources r JOIN scans s ON s.id=r.scan_id "
                       "WHERE r.account_id=? AND s.status IN ('ok','partial')", (account_id,))
        return row["id"] if row and row["id"] else None

    def add_scan_errors(self, scan_id: int, rows: list[tuple]) -> None:
        if rows:
            self.many("INSERT INTO scan_errors VALUES (?,?,?,?,?)",
                      [(scan_id, *r) for r in rows])

    def scan_errors(self, scan_id: int) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM scan_errors WHERE scan_id=? ORDER BY account_id, region",
                      (scan_id,))

    def prune(self, keep_scans: int = 30, keep_audit_days: int = 90) -> None:
        cutoff = self.one("SELECT id FROM scans ORDER BY id DESC LIMIT 1 OFFSET ?", (keep_scans - 1,))
        if cutoff:
            self.x("DELETE FROM scans WHERE id < ?", (cutoff["id"],))
        self.x("DELETE FROM api_calls WHERE ts < ?", (time.time() - keep_audit_days * 86400,))

    # -------------------------------------------------------------- inventory

    def add_resources(self, scan_id: int, resources: list) -> None:
        self.many(
            "INSERT OR REPLACE INTO resources VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(scan_id, r.arn, r.account_id, r.region, r.service, r.type, r.name,
              json.dumps(r.tags or {}), r.created, json.dumps(r.raw, default=str))
             for r in resources],
        )

    def resources(self, scan_id: int, account_id: Optional[str] = None) -> list[sqlite3.Row]:
        if account_id:
            return self.q("SELECT * FROM resources WHERE scan_id=? AND account_id=?",
                          (scan_id, account_id))
        return self.q("SELECT * FROM resources WHERE scan_id=?", (scan_id,))

    # --------------------------------------------------------------- findings

    def add_findings(self, scan_id: int, findings: list) -> None:
        self.many(
            "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(scan_id, f.check_id, f.arn, f.account_id, f.region, f.severity, f.title,
              f.evidence, f.remediation, f.source) for f in findings],
        )

    def suppress(self, check_id: str, arn: str, reason: str) -> None:
        self.x("INSERT OR REPLACE INTO suppressions VALUES (?,?,?,?)",
               (check_id, arn, reason, time.time()))

    def unsuppress(self, check_id: str, arn: str) -> None:
        self.x("DELETE FROM suppressions WHERE check_id=? AND arn=?", (check_id, arn))

    def suppressions(self) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM suppressions ORDER BY created_at DESC")

    # ------------------------------------------------------------------- cost

    def cost_fetched_at(self, account_id: str) -> float:
        row = self.one("SELECT fetched_at FROM cost_meta WHERE account_id=?", (account_id,))
        return row["fetched_at"] if row else 0.0

    def save_cost(self, account_id: str, daily: list[tuple[str, str, float]],
                  forecast: Optional[float], error: str = "") -> None:
        with self._lock:
            if daily:
                days = sorted({d for d, _, _ in daily})
                self.x("DELETE FROM cost_daily WHERE account_id=? AND day>=?", (account_id, days[0]))
                self.many("INSERT OR REPLACE INTO cost_daily VALUES (?,?,?,?)",
                          [(account_id, d, s, usd) for d, s, usd in daily])
            self.x("INSERT OR REPLACE INTO cost_meta VALUES (?,?,?,?)",
                   (account_id, time.time(), forecast, error))

    def add_resource_costs(self, scan_id: int, rows: list[tuple]) -> None:
        if rows:
            self.many("INSERT INTO resource_cost VALUES (?,?,?,?,?,?,?)",
                      [(scan_id, *r) for r in rows])

    # ------------------------------------------------------------------ audit

    def record_api_calls(self, rows: list[tuple]) -> None:
        self.many("INSERT INTO api_calls VALUES (?,?,?,?,?,?,?,?)", rows)


def pick_role(roles: list[str]) -> Optional[str]:
    """Default to the least-privileged role on offer: a read-only role over admin."""
    if not roles:
        return None
    ranked = sorted(roles, key=lambda r: (
        0 if "readonly" in r.lower().replace("-", "").replace("_", "") else
        1 if "viewonly" in r.lower().replace("-", "").replace("_", "") else
        2 if "securityaudit" in r.lower() else
        4 if "admin" in r.lower() else 3,
        r,
    ))
    return ranked[0]
