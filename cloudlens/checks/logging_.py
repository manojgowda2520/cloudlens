"""Logging and threat-detection checks, plus findings imported from GuardDuty / Security Hub."""
from __future__ import annotations

from typing import Iterator

from .base import Hit, View, check


@check("LOG-01", "High", "No multi-region CloudTrail is logging",
       "Create (or re-enable) a multi-region trail, ideally an organization trail to a locked-down bucket.")
def cloudtrail(view: View) -> Iterator[Hit]:
    acct = view.account()
    trails = view.of("cloudtrail", "trail")
    if not acct:
        return
    ok = [t for t in trails if t["raw"].get("IsMultiRegionTrail") and (t["raw"].get("Status") or {}).get("IsLogging")]
    if not ok:
        detail = (f"{len(trails)} trail(s), none multi-region and logging" if trails else "no trails")
        yield Hit(acct, detail)


def _settings(view: View) -> list[dict]:
    return view.of("account", "region-settings")


@check("LOG-02", "Medium", "GuardDuty is off in a region with resources",
       "Enable GuardDuty in every region you use (it is cheap and region-scoped).")
def guardduty(view: View) -> Iterator[Hit]:
    used = view.regions_in_use()
    for s in _settings(view):
        if s["region"] in used and s["raw"].get("GuardDuty") == "DISABLED":
            yield Hit(s, f"GuardDuty not enabled in {s['region']}")


@check("LOG-03", "Info", "Security Hub is off",
       "Enable Security Hub with the AWS Foundational Security Best Practices standard for continuous checks.")
def securityhub(view: View) -> Iterator[Hit]:
    used = view.regions_in_use()
    off = sorted(s["region"] for s in _settings(view) if s["region"] in used and not s["raw"].get("SecurityHub"))
    acct = view.account()
    if off and acct:
        yield Hit(acct, f"not enabled in {', '.join(off)}")


@check("LOG-04", "Low", "Log group keeps logs forever",
       "Set a retention period; unbounded retention grows the bill and keeps data longer than needed.")
def log_retention(view: View) -> Iterator[Hit]:
    for g in view.of("logs", "log-group"):
        if not g["raw"].get("retentionInDays"):
            gb = (g["raw"].get("storedBytes") or 0) / 1e9
            yield Hit(g, f"no retention; {gb:.2f} GB stored")


@check("AWS-GD", "High", "GuardDuty finding",
       "Investigate in the GuardDuty console; archive it there once resolved.")
def guardduty_findings(view: View) -> Iterator[Hit]:
    for s in _settings(view):
        for f in s["raw"].get("GuardDutyFindings") or []:
            sev = "Critical" if f.get("Severity", 0) >= 9 else "High"
            yield Hit(f"arn:aws:guardduty:{s['region']}:{view.account_id}:finding/{f['Id']}",
                      f"{f.get('Type')} on {f.get('ResourceType')}", severity=sev, title=f"GuardDuty: {f.get('Title')}")


@check("AWS-SH", "High", "Security Hub finding",
       "Follow the remediation in Security Hub; mark it resolved there once fixed.")
def securityhub_findings(view: View) -> Iterator[Hit]:
    for s in _settings(view):
        for f in s["raw"].get("SecurityHubFindings") or []:
            sev = "Critical" if f.get("Severity") == "CRITICAL" else "High"
            yield Hit(f.get("Resource") or f["Id"], f"Security Hub: {f.get('Title')}",
                      severity=sev, title=f"Security Hub: {f.get('Title')}",
                      remediation=f.get("Remediation") or None)
