"""The local dashboard.

Bound to 127.0.0.1 only. Two further guards, because "local" is not the same as
"private" for a web server: every request must carry a Host header naming the local
address (stops DNS-rebinding pages from reading it), and every POST must carry the
per-process CSRF token (stops other pages from driving it).
"""
from __future__ import annotations

import csv
import io
import json
import secrets as pysecrets
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..checks.base import checks as all_checks
from ..scan import MODULES
from ..sso import DeviceLogin, LoginRequired
from ..store import SEVERITIES
from ..workspace import Workspace
from . import queries as Q

HERE = Path(__file__).parent


def _ago(ts: Optional[float]) -> str:
    if not ts:
        return "never"
    s = time.time() - ts
    if s < 90:
        return "just now"
    if s < 3600:
        return f"{int(s // 60)} min ago"
    if s < 86400:
        return f"{int(s // 3600)} h ago"
    return f"{int(s // 86400)} d ago"


def _usd(v: Optional[float]) -> str:
    if v is None:
        return "–"
    return f"${v:,.0f}" if abs(v) >= 100 else f"${v:,.2f}"


def create_app(ws: Workspace, *, demo: bool = False, allowed_hosts: Optional[set] = None) -> FastAPI:
    app = FastAPI(title="cloudlens", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    env = templates.env
    env.filters["ago"] = _ago
    env.filters["usd"] = _usd
    env.filters["dt"] = lambda ts: datetime.fromtimestamp(ts).strftime("%d %b %H:%M") if ts else "–"
    env.filters["fromjson"] = json.loads
    env.filters["tojson_pretty"] = lambda v: json.dumps(v, indent=2, default=str, sort_keys=True)
    env.globals.update(SEVERITIES=SEVERITIES, version=__version__, demo=demo)

    token = pysecrets.token_urlsafe(32)
    hosts = allowed_hosts or set()
    logins: dict[str, DeviceLogin] = {}
    state = {"scan_thread": None}

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = (request.headers.get("host") or "").split(":")[0]
        if host not in {"127.0.0.1", "localhost"} | hosts:
            return PlainTextResponse("cloudlens only answers on 127.0.0.1", status_code=403)
        if request.method == "POST" and request.headers.get("x-csrf-token") != token:
            return PlainTextResponse("missing or bad CSRF token", status_code=403)
        resp = await call_next(request)
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    def page(request: Request, name: str, **ctx) -> HTMLResponse:
        p = ws.scanner.progress
        return templates.TemplateResponse(request, name, {
            "csrf": token, "nav": name.split(".")[0], "scan_running": p.running, "progress": p, **ctx})

    def redirect(url: str) -> Response:
        return Response(status_code=204, headers={"X-Redirect": url})

    # ------------------------------------------------------------------ pages

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request):
        accounts = Q.accounts_overview(ws.store)
        enabled = [a for a in accounts if a["enabled"]]
        totals = {s: sum(a["severity"][s] for a in enabled) for s in SEVERITIES}
        return page(request, "overview.html", accounts=enabled, totals=totals,
                    resources=sum(a["resources"] for a in enabled),
                    mtd=sum(a["mtd"] or 0 for a in enabled),
                    forecast=sum(a["forecast"] or 0 for a in enabled),
                    portals=ws.store.portals(), all_accounts=len(accounts),
                    last_scan=(ws.store.scans(1) or [None])[0])

    @app.get("/findings", response_class=HTMLResponse)
    def findings(request: Request, severity: str = "", account: str = "", check: str = "", q: str = "",
                 view: str = ""):
        rows = Q.findings(ws.store, severity=severity or None, account=account or None, check=check or None,
                          q=q or None, suppressed=view == "suppressed", new_only=view == "new")
        totals = Q.severity_totals(Q.findings(ws.store, account=account or None, check=check or None,
                                              q=q or None, suppressed=view == "suppressed",
                                              new_only=view == "new"))
        by_check: dict = {}
        for r in rows:
            by_check.setdefault(r["check_id"], []).append(r)
        return page(request, "findings.html", rows=rows, by_check=by_check, totals=totals,
                    checks=all_checks(), accounts=ws.store.accounts(enabled_only=True),
                    f={"severity": severity, "account": account, "check": check, "q": q, "view": view})

    @app.get("/inventory", response_class=HTMLResponse)
    def inventory(request: Request, account: str = "", region: str = "", service: str = "", q: str = ""):
        rows, total = Q.inventory(ws.store, account=account or None, region=region or None,
                                  service=service or None, q=q or None)
        return page(request, "inventory.html", rows=rows, total=total, facets=Q.facets(ws.store),
                    accounts=ws.store.accounts(enabled_only=True),
                    f={"account": account, "region": region, "service": service, "q": q})

    @app.get("/resource", response_class=HTMLResponse)
    def resource(request: Request, arn: str):
        r = Q.resource(ws.store, arn)
        if not r:
            return HTMLResponse("not found", status_code=404)
        return page(request, "resource.html", r=r, account=ws.store.account(r["account_id"]))

    @app.get("/cost", response_class=HTMLResponse)
    def cost(request: Request):
        return page(request, "cost.html", c=Q.cost_summary(ws.store))

    @app.get("/scans", response_class=HTMLResponse)
    def scans(request: Request):
        return page(request, "scans.html", scans=ws.store.scans(50), modules=MODULES)

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    def scan_detail(request: Request, scan_id: int):
        s = ws.store.scan(scan_id)
        if not s:
            return HTMLResponse("not found", status_code=404)
        prev = ws.store.one("SELECT id FROM scans WHERE id<? AND status IN ('ok','partial') ORDER BY id DESC LIMIT 1",
                            (scan_id,))
        d = Q.diff(ws.store, prev["id"], scan_id) if prev else None
        return page(request, "scan.html", s=s, errors=ws.store.scan_errors(scan_id), diff=d,
                    prev_id=prev["id"] if prev else None)

    @app.get("/diff", response_class=HTMLResponse)
    def diff(request: Request, a: int, b: int):
        return page(request, "diff.html", d=Q.diff(ws.store, a, b), a=a, b=b)

    @app.get("/portals", response_class=HTMLResponse)
    def portals(request: Request):
        items = []
        for p in ws.store.portals():
            portal = ws.portals[p["id"]]
            items.append({**dict(p), "expires": portal.token_expires_at(), "logged_in": portal.logged_in(),
                          "accounts": [dict(a) for a in ws.store.accounts(portal_id=p["id"])]})
        return page(request, "portals.html", portals=items)

    @app.get("/audit", response_class=HTMLResponse)
    def audit(request: Request, outcome: str = ""):
        sql, args = "SELECT * FROM api_calls", []
        if outcome:
            sql += " WHERE outcome=?" if outcome != "fail" else " WHERE outcome NOT IN ('ok','blocked')"
            if outcome != "fail":
                args.append(outcome)
        rows = ws.store.q(sql + " ORDER BY ts DESC LIMIT 500", args)
        stats = ws.store.one("SELECT COUNT(*) n, SUM(outcome='blocked') blocked, "
                             "SUM(outcome NOT IN ('ok','blocked')) failed FROM api_calls")
        top = ws.store.q("SELECT service, operation, COUNT(*) n FROM api_calls GROUP BY service, operation "
                         "ORDER BY n DESC LIMIT 15")
        return page(request, "audit.html", rows=rows, stats=stats, top=top, outcome=outcome)

    @app.get("/report/{account_id}", response_class=HTMLResponse)
    def report(request: Request, account_id: str):
        acct = ws.store.account(account_id)
        if not acct:
            return HTMLResponse("not found", status_code=404)
        rows = Q.findings(ws.store, account=account_id)
        ov = next((a for a in Q.accounts_overview(ws.store) if a["account_id"] == account_id), None)
        return templates.TemplateResponse(request, "report.html", {
            "acct": acct, "rows": rows, "ov": ov, "totals": Q.severity_totals(rows),
            "generated": datetime.now().strftime("%d %b %Y %H:%M")})

    # ---------------------------------------------------------------- exports

    def _csv(name: str, header: list, rows) -> Response:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(header)
        w.writerows(rows)
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.get("/export/findings.csv")
    def export_findings():
        rows = Q.findings(ws.store, limit=100000)
        return _csv("cloudlens-findings.csv",
                    ["severity", "check", "title", "account", "account_name", "region", "resource", "evidence",
                     "remediation", "source"],
                    [[r["severity"], r["check_id"], r["title"], r["account_id"], r["account_name"], r["region"],
                      r["arn"], r["evidence"], r["remediation"], r["source"]] for r in rows])

    @app.get("/export/inventory.csv")
    def export_inventory():
        rows, _ = Q.inventory(ws.store, limit=1000000)
        return _csv("cloudlens-inventory.csv",
                    ["account", "account_name", "region", "service", "type", "name", "arn", "created", "tags"],
                    [[r["account_id"], r["account_name"], r["region"], r["service"], r["type"], r["name"],
                      r["arn"], r["created"], json.dumps(r["tags"])] for r in rows])

    # ------------------------------------------------------------------- scan

    @app.post("/scan")
    def start_scan(modules: str = Form("inventory,security,cost"), force_cost: str = Form("")):
        if demo:
            return PlainTextResponse("Scanning is disabled in demo mode.", status_code=400)
        if ws.scanner.progress.running:
            return PlainTextResponse("A scan is already running.", status_code=409)
        if not ws.store.accounts(enabled_only=True):
            return PlainTextResponse("Enable at least one account on the Portals page first.", status_code=400)
        mods = [m for m in modules.split(",") if m in MODULES]
        t = threading.Thread(target=lambda: ws.scanner.run(mods, force_cost=bool(force_cost)),
                             daemon=True, name="scan")
        t.start()
        state["scan_thread"] = t
        time.sleep(0.2)
        return redirect("/scans")

    @app.get("/scan/status")
    def scan_status():
        p = ws.scanner.progress
        return JSONResponse({"running": p.running, "phase": p.phase, "done": p.done, "total": p.total,
                             "scan_id": p.scan_id, "elapsed": int(time.time() - p.started) if p.started else 0,
                             "log": [m for _, m in p.log[-8:]]})

    # ---------------------------------------------------------------- portals

    @app.post("/portals")
    def add_portal(name: str = Form(...), start_url: str = Form(...), sso_region: str = Form(...)):
        try:
            portal = ws.add_portal(name, start_url, sso_region)
        except ValueError as exc:
            return PlainTextResponse(str(exc), status_code=400)
        return redirect(f"/portals#{portal.id}")

    @app.post("/portals/{pid}/login")
    def start_login(pid: str):
        portal = ws.portals.get(pid)
        if not portal:
            return PlainTextResponse("no such portal", status_code=404)
        try:
            logins[pid] = portal.start_login()
        except Exception as exc:  # noqa: BLE001
            return PlainTextResponse(f"Could not start sign-in: {exc}", status_code=502)
        return JSONResponse({"url": logins[pid].verification_url, "code": logins[pid].user_code,
                             "interval": logins[pid].interval})

    @app.post("/portals/{pid}/poll")
    def poll_login(pid: str):
        portal, login = ws.portals.get(pid), logins.get(pid)
        if not portal or not login:
            return JSONResponse({"state": "none"})
        try:
            if not portal.poll(login):
                return JSONResponse({"state": "pending", "interval": login.interval})
        except LoginRequired as exc:
            logins.pop(pid, None)
            return JSONResponse({"state": "failed", "message": str(exc)})
        logins.pop(pid, None)
        try:
            seen, skipped = ws.discover(pid)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse({"state": "done", "message": f"Signed in, but discovery failed: {exc}"})
        return JSONResponse({"state": "done", "message": f"Signed in. {seen} accounts found"
                                                         + (f", {skipped} already under another portal" if skipped else "")})

    @app.post("/portals/{pid}/discover")
    def discover(pid: str):
        try:
            ws.discover(pid)
        except LoginRequired as exc:
            return PlainTextResponse(str(exc), status_code=401)
        return redirect(f"/portals#{pid}")

    @app.post("/portals/{pid}/remove")
    def remove(pid: str):
        ws.remove_portal(pid)
        return redirect("/portals")

    @app.post("/portals/{pid}/logout")
    def logout(pid: str):
        if pid in ws.portals:
            ws.portals[pid].logout()
        return redirect(f"/portals#{pid}")

    @app.post("/accounts/{account_id}")
    def update_account(account_id: str, enabled: str = Form(""), role_name: str = Form(""),
                       regions: str = Form(""), field: str = Form("")):
        if field == "enabled":
            ws.store.set_account(account_id, enabled=enabled == "1")
        elif field == "role" and role_name:
            ws.store.set_account(account_id, role_name=role_name)
        elif field == "regions":
            rs = [r.strip() for r in regions.replace(",", " ").split() if r.strip()]
            ws.store.set_account(account_id, regions=rs or None, clear_regions=not rs)
        return Response(status_code=204)

    @app.post("/accounts/bulk/{pid}")
    def bulk(pid: str, enabled: str = Form("1")):
        for a in ws.store.accounts(portal_id=pid):
            ws.store.set_account(a["account_id"], enabled=enabled == "1")
        return redirect(f"/portals#{pid}")

    # ------------------------------------------------------------ suppression

    @app.post("/suppress")
    def suppress(check_id: str = Form(...), arn: str = Form(...), reason: str = Form(...)):
        if not reason.strip():
            return PlainTextResponse("a reason is required", status_code=400)
        ws.store.suppress(check_id, arn, reason.strip())
        return Response(status_code=204)

    @app.post("/unsuppress")
    def unsuppress(check_id: str = Form(...), arn: str = Form(...)):
        ws.store.unsuppress(check_id, arn)
        return Response(status_code=204)

    return app


def serve(port: int = 8080, demo: bool = False, open_browser: bool = True) -> int:
    import uvicorn

    from .. import paths
    paths.ensure()
    if demo:
        from ..demo import build
        db = paths.home() / "demo.db"
        build(db)
        ws = Workspace(db_path=db)
    else:
        ws = Workspace()
    app = create_app(ws, demo=demo)
    url = f"http://127.0.0.1:{port}/"
    print(f"cloudlens {'(demo) ' if demo else ''}on {url}  - Ctrl+C to stop")
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    finally:
        ws.close()
    return 0
