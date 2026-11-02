"""Network exposure checks."""
from __future__ import annotations

from typing import Iterator

from .base import Hit, View, check

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle", 27017: "MongoDB",
            6379: "Redis", 9200: "Elasticsearch", 5984: "CouchDB", 9042: "Cassandra", 11211: "Memcached"}
OPEN = ("0.0.0.0/0", "::/0")
OLD_TLS = {"ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-TLS-1-0-2015-04", "ELBSecurityPolicy-TLS-1-1-2017-01",
           "ELBSecurityPolicy-2015-05", "ELBSecurityPolicy-FS-2018-06", "ELBSecurityPolicy-FS-1-1-2019-08"}


def _open_rules(sg: dict) -> Iterator[tuple[int, int, str]]:
    """(from_port, to_port, cidr) for every ingress rule open to the internet."""
    for p in sg["raw"].get("IpPermissions") or []:
        cidrs = [r.get("CidrIp") for r in p.get("IpRanges") or []] + \
                [r.get("CidrIpv6") for r in p.get("Ipv6Ranges") or []]
        for cidr in cidrs:
            if cidr in OPEN:
                if p.get("IpProtocol") == "-1":
                    yield 0, 65535, cidr
                else:
                    yield p.get("FromPort", 0), p.get("ToPort", 65535), cidr


def _sg_hits(view: View, ports: dict) -> Iterator[Hit]:
    for sg in view.of("ec2", "security-group"):
        found = []
        for lo, hi, cidr in _open_rules(sg):
            if lo == 0 and hi == 65535:
                continue   # reported once, by NET-03
            found += [f"{name} ({port}) from {cidr}" for port, name in ports.items() if lo <= port <= hi]
        if found:
            in_use = sg["raw"].get("InUse")
            yield Hit(sg, "; ".join(sorted(set(found))) + ("" if in_use else " - not attached to anything"),
                      severity=None if in_use else "Low")


@check("NET-01", "Critical", "Security group opens SSH/RDP to the internet",
       "Restrict the source to known IPs, or drop the rule and use SSM Session Manager.")
def sg_admin(view: View) -> Iterator[Hit]:
    yield from _sg_hits(view, ADMIN_PORTS)


@check("NET-02", "Critical", "Security group opens a database port to the internet",
       "Allow the database port only from the application's security group.")
def sg_db(view: View) -> Iterator[Hit]:
    yield from _sg_hits(view, DB_PORTS)


@check("NET-03", "Critical", "Security group allows all ports from the internet",
       "Replace the all-traffic rule with the specific ports the service needs.")
def sg_all(view: View) -> Iterator[Hit]:
    for sg in view.of("ec2", "security-group"):
        wide = [cidr for lo, hi, cidr in _open_rules(sg) if lo == 0 and hi == 65535]
        if wide:
            in_use = sg["raw"].get("InUse")
            yield Hit(sg, f"all traffic from {', '.join(sorted(set(wide)))}" + ("" if in_use else " - not attached"),
                      severity=None if in_use else "Low")


@check("NET-04", "Medium", "Default security group in use and has rules",
       "Remove all rules from the default security group and give resources purpose-built groups.")
def default_sg(view: View) -> Iterator[Hit]:
    for sg in view.of("ec2", "security-group"):
        raw = sg["raw"]
        if raw.get("GroupName") == "default" and raw.get("InUse") and \
                (raw.get("IpPermissions") or raw.get("IpPermissionsEgress")):
            yield Hit(sg, f"{len(raw.get('IpPermissions') or [])} ingress / "
                          f"{len(raw.get('IpPermissionsEgress') or [])} egress rules")


@check("NET-05", "Medium", "VPC in use has no flow logs",
       "Enable VPC flow logs (to CloudWatch Logs or S3) so traffic can be investigated after an incident.")
def flow_logs(view: View) -> Iterator[Hit]:
    used = {sg["raw"].get("VpcId") for sg in view.of("ec2", "security-group") if sg["raw"].get("InUse")}
    for v in view.of("ec2", "vpc"):
        if v["raw"].get("VpcId") in used and not v["raw"].get("FlowLogs"):
            yield Hit(v, "no flow log on this VPC")


@check("NET-06", "High", "RDS database is publicly accessible",
       "Set PubliclyAccessible to false and reach the database through the VPC.")
def rds_public(view: View) -> Iterator[Hit]:
    for db in view.of("rds", "instance"):
        if db["raw"].get("PubliclyAccessible"):
            ep = (db["raw"].get("Endpoint") or {}).get("Address", "")
            yield Hit(db, f"PubliclyAccessible = true ({ep})")


@check("NET-07", "High", "EC2 instance allows IMDSv1",
       "Require IMDSv2 (HttpTokens = required); IMDSv1 is the classic SSRF-to-credentials path.")
def imdsv1(view: View) -> Iterator[Hit]:
    for i in view.of("ec2", "instance"):
        md = i["raw"].get("MetadataOptions") or {}
        if md.get("HttpEndpoint", "enabled") == "enabled" and md.get("HttpTokens") == "optional":
            public = i["raw"].get("PublicIpAddress")
            yield Hit(i, "HttpTokens = optional" + (f", public IP {public}" if public else ""),
                      severity=None if public else "Medium")


@check("NET-08", "Medium", "Load balancer serves plain HTTP or an outdated TLS policy",
       "Redirect HTTP to HTTPS and use a current policy such as ELBSecurityPolicy-TLS13-1-2-2021-06.")
def lb_tls(view: View) -> Iterator[Hit]:
    for lb in view.of("elbv2", "application") + view.of("elbv2", "network"):
        problems = []
        for li in lb["raw"].get("Listeners") or []:
            if li.get("Protocol") == "HTTP":
                redirects = any(a.get("Type") == "redirect" for a in li.get("DefaultActions") or [])
                if not redirects:
                    problems.append(f"HTTP:{li.get('Port')} without redirect")
            if li.get("SslPolicy") in OLD_TLS:
                problems.append(f"{li.get('Protocol')}:{li.get('Port')} uses {li['SslPolicy']}")
        if problems and lb["raw"].get("Scheme") == "internet-facing":
            yield Hit(lb, "; ".join(problems))
    for lb in view.of("elb", "classic"):
        http = [d["Listener"]["LoadBalancerPort"] for d in lb["raw"].get("ListenerDescriptions") or []
                if d["Listener"].get("Protocol") == "HTTP"]
        if http and lb["raw"].get("Scheme") == "internet-facing":
            yield Hit(lb, f"classic load balancer serves HTTP on {http}")


@check("NET-09", "Medium", "EKS API endpoint is public to the whole internet",
       "Disable public endpoint access, or restrict publicAccessCidrs to your office/VPN ranges.")
def eks_public(view: View) -> Iterator[Hit]:
    for c in view.of("eks", "cluster"):
        vpc = c["raw"].get("resourcesVpcConfig") or {}
        if vpc.get("endpointPublicAccess") and "0.0.0.0/0" in (vpc.get("publicAccessCidrs") or ["0.0.0.0/0"]):
            yield Hit(c, "endpointPublicAccess = true, publicAccessCidrs includes 0.0.0.0/0")
