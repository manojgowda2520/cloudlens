"""Domain, DNS and certificate checks."""
from __future__ import annotations

import re
from typing import Iterator, Optional

from .base import Hit, View, check, parse_time

_S3_HOST = re.compile(r"^(?P<bucket>.+?)\.s3(?:[.-]website)?(?:[.-][a-z0-9-]+)?\.amazonaws\.com\.?$")
_OLD_CF_TLS = {"SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016"}


@check("DNS-01", "High", "Domain registration expiring or auto-renew off",
       "Turn on auto-renew in Route 53 Domains and make sure the payment method is current.")
def domain_expiry(view: View) -> Iterator[Hit]:
    for d in view.of("route53domains", "domain"):
        problems = []
        expiry = parse_time(d["raw"].get("Expiry"))
        if expiry:
            days = (expiry - view.now).days
            if days < 30:
                problems.append(f"expires in {days} days ({expiry.date()})")
        if d["raw"].get("AutoRenew") is False:
            problems.append("AutoRenew = false")
        if problems:
            yield Hit(d, "; ".join(problems), severity="Critical" if expiry and (expiry - view.now).days < 7 else None)


@check("DNS-02", "Medium", "Domain transfer lock is off",
       "Enable the transfer lock so the domain cannot be moved to another registrar without you.")
def domain_lock(view: View) -> Iterator[Hit]:
    for d in view.of("route53domains", "domain"):
        if d["raw"].get("TransferLock") is False:
            yield Hit(d, "TransferLock = false")


def _dangling(view: View, target: str) -> Optional[str]:
    t = target.lower().rstrip(".")
    sh = view.shared
    m = _S3_HOST.match(t + ".")
    if m and "amazonaws.com" in t and ".s3" in t:
        bucket = m.group("bucket")
        if bucket not in sh.bucket_names:
            return f"points at S3 bucket '{bucket}', which no scanned account owns"
    if t.endswith(".cloudfront.net") and t not in sh.cloudfront_domains:
        return f"points at CloudFront {t}, which no scanned distribution uses"
    if t.endswith(".elasticbeanstalk.com") and t not in sh.beanstalk_cnames:
        return f"points at Elastic Beanstalk {t}, which no scanned environment uses"
    if t.endswith(".elb.amazonaws.com"):
        host = t[len("dualstack."):] if t.startswith("dualstack.") else t
        if host not in sh.elb_dns_names:
            return f"points at load balancer {host}, which no scanned account owns"
    return None


@check("DNS-03", "High", "DNS record points at an AWS resource that no longer exists",
       "Delete the record, or recreate the target. A dangling record lets anyone who claims the target "
       "serve content on your domain (subdomain takeover). If the target lives in an account cloudlens "
       "cannot see, add that account or suppress this finding.")
def dangling_dns(view: View) -> Iterator[Hit]:
    for z in view.of("route53", "hosted-zone"):
        if (z["raw"].get("Config") or {}).get("PrivateZone"):
            continue
        for r in z["raw"].get("Records") or []:
            targets = ([r["Alias"]] if r.get("Alias") else []) + \
                      (r.get("Values") or [] if r.get("Type") == "CNAME" else [])
            for t in targets:
                why = _dangling(view, t)
                if why:
                    yield Hit(z, f"{r['Name'].rstrip('.')} ({r['Type']}) {why}")


@check("DNS-04", "High", "Certificate in use is expiring or failing renewal",
       "Fix DNS/email validation so ACM can renew, or replace the certificate before it expires.")
def cert_expiry(view: View) -> Iterator[Hit]:
    for c in view.of("acm", "certificate"):
        raw = c["raw"]
        in_use = bool(raw.get("InUseBy"))
        problems = []
        after = parse_time(raw.get("NotAfter"))
        if after:
            days = (after - view.now).days
            if days < 0:
                problems.append(f"expired {-days} days ago")
            elif days < 30:
                problems.append(f"expires in {days} days")
        renewal = (raw.get("RenewalSummary") or {}).get("RenewalStatus")
        if renewal == "FAILED":
            problems.append("renewal FAILED")
        if problems:
            sev = None if in_use else "Low"
            if in_use and after and after < view.now:
                sev = "Critical"
            yield Hit(c, "; ".join(problems) + (f"; in use by {len(raw['InUseBy'])} resources" if in_use
                                                 else "; not in use"), severity=sev)


@check("DNS-05", "Medium", "CloudFront allows HTTP or old TLS",
       "Set viewer protocol policy to redirect-to-https and minimum protocol version to TLSv1.2_2021.")
def cloudfront_tls(view: View) -> Iterator[Hit]:
    for d in view.of("cloudfront", "distribution"):
        raw = d["raw"]
        problems = []
        behaviors = [raw.get("DefaultCacheBehavior") or {}] + ((raw.get("CacheBehaviors") or {}).get("Items") or [])
        allow_all = [b.get("PathPattern", "default") for b in behaviors if b.get("ViewerProtocolPolicy") == "allow-all"]
        if allow_all:
            problems.append(f"ViewerProtocolPolicy = allow-all on {', '.join(allow_all)}")
        cert = raw.get("ViewerCertificate") or {}
        if not cert.get("CloudFrontDefaultCertificate") and cert.get("MinimumProtocolVersion") in _OLD_CF_TLS:
            problems.append(f"MinimumProtocolVersion = {cert['MinimumProtocolVersion']}")
        if problems:
            yield Hit(d, "; ".join(problems))
