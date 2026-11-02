"""Shared wiring for the CLI and the web app: one store, one audit log, the portals."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from . import guard, paths
from .scan import Scanner
from .sso import Portal, slugify
from .store import Store


class Workspace:
    def __init__(self, db_path: Optional[Path] = None, workers: int = 16):
        paths.ensure()
        self.store = Store(db_path or paths.database())
        self.audit = guard.AuditLog(sink=self.store.record_api_calls)
        self.portals: dict[str, Portal] = {}
        self.reload_portals()
        self.scanner = Scanner(self.store, self.portals, self.audit, workers=workers)

    def reload_portals(self) -> None:
        self.portals.clear()
        for row in self.store.portals():
            self.portals[row["id"]] = Portal(row["id"], row["start_url"], row["sso_region"], audit=self.audit)

    def add_portal(self, name: str, start_url: str, sso_region: str) -> Portal:
        start_url = start_url.strip().rstrip("/")
        if not start_url.startswith("https://"):
            raise ValueError("start URL must begin with https://")
        if any(p.start_url == start_url for p in self.portals.values()):
            raise ValueError("that start URL is already added")
        base = slugify(name)
        pid, n = base, 2
        while pid in self.portals:
            pid, n = f"{base}-{n}", n + 1
        self.store.add_portal(pid, name.strip(), start_url, sso_region.strip())
        self.reload_portals()
        return self.portals[pid]

    def remove_portal(self, portal_id: str) -> None:
        portal = self.portals.get(portal_id)
        if portal:
            portal.logout()
        self.store.delete_portal(portal_id)
        self.reload_portals()

    def discover(self, portal_id: str) -> tuple[int, int]:
        """Refresh the account list behind a portal. Returns (seen, skipped as duplicates)."""
        accounts = self.portals[portal_id].discover()
        skipped = 0
        for a in accounts:
            if not self.store.upsert_discovered(portal_id, a["account_id"], a["name"], a["email"], a["roles"]):
                skipped += 1
        self.audit.flush()
        return len(accounts), skipped

    def close(self) -> None:
        self.audit.flush()
        self.store.close()
