"""Dashboard commands: portals, accounts, scans, the web UI, audit and export."""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
import webbrowser
from datetime import datetime

from .store import SEVERITIES


def register(sub) -> None:
    serve = sub.add_parser("serve", help="start the local dashboard")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--demo", action="store_true", help="use a synthetic demo dataset, not real accounts")
    serve.add_argument("--no-browser", action="store_true")

    portal = sub.add_parser("portal", help="manage SSO portals")
    psub = portal.add_subparsers(dest="portal_cmd", required=True)
    add = psub.add_parser("add", help="add an SSO portal and sign in")
    add.add_argument("--name", required=True)
    add.add_argument("--start-url", required=True, help="e.g. https://my-org.awsapps.com/start")
    add.add_argument("--region", required=True, help="the IAM Identity Center region")
    psub.add_parser("list")
    login = psub.add_parser("login", help="sign in again")
    login.add_argument("portal_id")
    disc = psub.add_parser("discover", help="refresh the account list")
    disc.add_argument("portal_id")
    rm = psub.add_parser("remove")
    rm.add_argument("portal_id")

    acc = sub.add_parser("accounts", help="list accounts and choose which to scan")
    acc.add_argument("--enable", nargs="*", metavar="ACCOUNT_ID", help="enable these (or 'all')")
    acc.add_argument("--disable", nargs="*", metavar="ACCOUNT_ID")
    acc.add_argument("--role", nargs=2, metavar=("ACCOUNT_ID", "ROLE"))
    acc.add_argument("--regions", nargs="+", metavar=("ACCOUNT_ID", "REGION"),
                     help="limit an account to these regions ('all' to reset)")

    scan = sub.add_parser("scan", help="scan enabled accounts")
    scan.add_argument("--modules", default="inventory,security,cost",
                      help="comma list of inventory,security,cost,resource-cost")
    scan.add_argument("--account", action="append", help="only this account (repeatable)")
    scan.add_argument("--force-cost", action="store_true", help="refresh Cost Explorer even if cached")
    scan.add_argument("--workers", type=int, default=16)

    sub.add_parser("checks", help="list security checks")

    audit = sub.add_parser("audit", help="show the AWS API call log")
    audit.add_argument("--writes", action="store_true", help="only blocked (non-read) calls - should be empty")
    audit.add_argument("--limit", type=int, default=50)

    export = sub.add_parser("export", help="export the latest scan as CSV")
    export.add_argument("what", choices=["findings", "inventory"])
    export.add_argument("-o", "--output", default="-")

    sched = sub.add_parser("schedule", help="print a launchd job that scans nightly")
    sched.add_argument("--hour", type=int, default=2)


COMMANDS = {"serve", "portal", "accounts", "scan", "checks", "audit", "export", "schedule"}


def dispatch(args: argparse.Namespace) -> int:
    if args.command == "checks":
        return _checks()
    if args.command == "schedule":
        return _schedule(args)
    if args.command == "serve":
        from .web.app import serve
        return serve(port=args.port, demo=args.demo, open_browser=not args.no_browser)

    from .workspace import Workspace
    ws = Workspace(workers=getattr(args, "workers", 16))
    try:
        return {"portal": _portal, "accounts": _accounts, "scan": _scan,
                "audit": _audit, "export": _export}[args.command](ws, args)
    finally:
        ws.close()


def _portal(ws, args) -> int:
    from .sso import LoginRequired
    if args.portal_cmd == "list":
        for p in ws.store.portals():
            exp = ws.portals[p["id"]].token_expires_at()
            state = "signed in until " + datetime.fromtimestamp(exp).strftime("%H:%M") \
                if exp and exp > time.time() else "signed out"
            n = len(ws.store.accounts(portal_id=p["id"]))
            print(f"{p['id']:20} {p['name']:24} {n:3} accounts  {state:24} {p['start_url']}")
        return 0
    if args.portal_cmd == "remove":
        ws.remove_portal(args.portal_id)
        return 0
    if args.portal_cmd == "add":
        portal = ws.add_portal(args.name, args.start_url, args.region)
    else:
        portal = ws.portals.get(args.portal_id)
        if not portal:
            print(f"no portal {args.portal_id}", file=sys.stderr)
            return 1
    if args.portal_cmd in ("add", "login"):
        login = portal.start_login()
        print(f"Approve the sign-in in your browser. Code: {login.user_code}\n{login.verification_url}")
        webbrowser.open(login.verification_url)
        try:
            portal.wait_for_login(login)
        except LoginRequired as exc:
            print(f"sign-in failed: {exc}", file=sys.stderr)
            return 1
        print("signed in.")
    seen, skipped = ws.discover(portal.id)
    print(f"{seen} accounts found" + (f" ({skipped} already added through another portal)" if skipped else ""))
    print("enable the ones to scan with: cloudlens accounts --enable <id> ... (or --enable all)")
    return 0


def _accounts(ws, args) -> int:
    st = ws.store
    if args.enable is not None:
        ids = [a["account_id"] for a in st.accounts()] if args.enable in (["all"], []) else args.enable
        for i in ids:
            st.set_account(i, enabled=True)
    for i in args.disable or []:
        st.set_account(i, enabled=False)
    if args.role:
        st.set_account(args.role[0], role_name=args.role[1])
    if args.regions:
        acct, regions = args.regions[0], args.regions[1:]
        st.set_account(acct, regions=None if regions == ["all"] else regions, clear_regions=regions == ["all"])
    for a in st.accounts():
        regions = ",".join(json.loads(a["regions"])) if a["regions"] else "all regions"
        print(f"{'[x]' if a['enabled'] else '[ ]'} {a['account_id']}  {a['name']:28} {a['portal_name']:20} "
              f"role={a['role_name'] or '-':28} {regions}")
    return 0


def _scan(ws, args) -> int:
    import logging
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s %(message)s")
    modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    if not ws.store.accounts(enabled_only=True):
        print("no accounts enabled - run `cloudlens accounts --enable ...` first", file=sys.stderr)
        return 1
    import threading
    result = {}
    t = threading.Thread(target=lambda: result.setdefault("id", ws.scanner.run(
        modules, args.account, force_cost=args.force_cost)), daemon=True)
    t.start()
    shown = 0
    while t.is_alive():
        t.join(1)
        p = ws.scanner.progress
        for _, msg in p.log[shown:] if len(p.log) > shown else []:
            print(f"  {msg}")
        shown = len(p.log)
        sys.stdout.write(f"\r{p.phase}: {p.done}/{p.total}   ")
        sys.stdout.flush()
    scan = ws.store.scan(result.get("id", 0))
    if not scan:
        return 1
    print(f"\nscan {scan['id']} {scan['status']}: {scan['accounts']} accounts, {scan['resources']} resources, "
          f"{scan['findings']} findings, {scan['errors']} errors ({scan['finished_at'] - scan['started_at']:.0f}s)")
    if ws.audit.blocked:
        print(f"WARNING: {ws.audit.blocked} non-read calls were blocked - see `cloudlens audit --writes`")
    return 0 if scan["status"] in ("ok", "partial") else 1


def _checks() -> int:
    from .checks.base import checks
    for c in sorted(checks().values(), key=lambda c: c.id):
        print(f"{c.id:8} {c.severity:9} {c.title}")
    return 0


def _audit(ws, args) -> int:
    sql = "SELECT * FROM api_calls"
    if args.writes:
        sql += " WHERE outcome='blocked'"
    rows = ws.store.q(sql + " ORDER BY ts DESC LIMIT ?", (args.limit,))
    total = ws.store.one("SELECT COUNT(*) n, SUM(outcome='blocked') b FROM api_calls")
    for r in rows:
        print(f"{datetime.fromtimestamp(r['ts']):%Y-%m-%d %H:%M:%S} {r['account_id'] or '-':12} "
              f"{r['region'] or '-':14} {r['service']}:{r['operation']:40} {r['outcome']}")
    print(f"{total['n']} calls logged, {total['b'] or 0} blocked")
    return 0


def _export(ws, args) -> int:
    scan_id = ws.store.latest_scan_id()
    if not scan_id:
        print("no completed scan yet", file=sys.stderr)
        return 1
    out = sys.stdout if args.output == "-" else open(args.output, "w", newline="")
    w = csv.writer(out)
    if args.what == "findings":
        order = {s: i for i, s in enumerate(SEVERITIES)}
        rows = sorted(ws.store.q("SELECT * FROM findings WHERE scan_id=?", (scan_id,)),
                      key=lambda r: (order.get(r["severity"], 9), r["check_id"]))
        w.writerow(["severity", "check", "title", "account", "region", "resource", "evidence", "remediation"])
        for r in rows:
            w.writerow([r["severity"], r["check_id"], r["title"], r["account_id"], r["region"], r["arn"],
                        r["evidence"], r["remediation"]])
    else:
        w.writerow(["account", "region", "service", "type", "name", "arn", "created", "tags"])
        for r in ws.store.resources(scan_id):
            w.writerow([r["account_id"], r["region"], r["service"], r["type"], r["name"], r["arn"],
                        r["created"], r["tags"]])
    if out is not sys.stdout:
        out.close()
    return 0


def _schedule(args) -> int:
    exe = sys.executable
    print(f"""<?xml version="1.0" encoding="UTF-8"?>
<!-- Save as ~/Library/LaunchAgents/com.cloudlens.scan.plist, then:
     launchctl load ~/Library/LaunchAgents/com.cloudlens.scan.plist
     Scans need a valid SSO session; expired portals are skipped and show up as errors. -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.cloudlens.scan</string>
  <key>ProgramArguments</key><array><string>{exe}</string><string>-m</string><string>cloudlens</string><string>scan</string></array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>{args.hour}</integer><key>Minute</key><integer>0</integer></dict>
  <key>StandardOutPath</key><string>/tmp/cloudlens-scan.log</string>
  <key>StandardErrorPath</key><string>/tmp/cloudlens-scan.log</string>
</dict></plist>""")
    return 0
