"""Command line entry point."""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from collections import defaultdict
from pathlib import Path

from prometheus_client import start_http_server

from . import __version__
from .cost.base import registry as estimator_registry
from .cost.collector import Collector
from . import paths
from .config import Config
from .cost.exporter import CostRegistry, build_registry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cloudlens",
        description="One local dashboard for every AWS account: inventory, security posture and cost.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="collect continuously and serve /metrics")
    run.add_argument("-c", "--config", default=None,
                     help="config file (default: ~/.cloudlens/config.yaml)")

    once = sub.add_parser("once", help="run one sweep and print the result")
    once.add_argument("-c", "--config", default=None,
                     help="config file (default: ~/.cloudlens/config.yaml)")
    once.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    once.add_argument("--top", type=int, default=40, help="rows to print (default 40)")

    sub.add_parser("estimators", help="list registered estimators")

    policy = sub.add_parser(
        "iam-policy",
        help="print the least-privilege IAM policy the enabled estimators need",
    )
    policy.add_argument("-c", "--config", default=None,
                        help="restrict to the estimators this config enables")

    args = parser.parse_args(argv)

    if args.command == "estimators":
        return _cmd_estimators()
    if args.command == "iam-policy":
        return _cmd_iam_policy(args)

    paths.ensure()
    config_path = args.config or paths.config_file()
    if not Path(config_path).is_file():
        print(f"cloudlens: no config at {config_path} - copy config.example.yaml there to start.",
              file=sys.stderr)
        return 2
    config = Config.load(config_path)
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)-24s %(message)s",
    )

    cost_registry = CostRegistry(
        tag_keys=tuple(config.tag_keys),
        top_n=config.top_n,
        min_usd_per_hour=config.min_usd_per_hour,
    )
    collector = Collector(config, cost_registry)

    if args.command == "once":
        return _cmd_once(collector, args)
    return _cmd_run(collector, cost_registry, config)


def _cmd_estimators() -> int:
    rows = []
    for name, cls in sorted(estimator_registry().items()):
        rows.append((name, cls.tier.value, cls.cadence,
                     "global" if cls.global_service else "regional"))
    width = max(len(r[0]) for r in rows)
    print(f"{'ESTIMATOR'.ljust(width)}  TIER       CADENCE     SCOPE")
    for name, tier, cadence, scope in rows:
        print(f"{name.ljust(width)}  {tier:<9}  {cadence:<10}  {scope}")
    return 0


def _cmd_iam_policy(args) -> int:
    all_estimators = estimator_registry()
    if args.config:
        config = Config.load(args.config)
        enabled = set(config.estimators) or set(all_estimators)
        if "*" in enabled:
            enabled = set(all_estimators)
        enabled -= set(config.disabled_estimators)
    else:
        enabled = set(all_estimators)

    actions = set()
    for name in sorted(enabled):
        cls = all_estimators.get(name)
        if cls:
            actions.update(cls.required_actions)
    actions.add("sts:GetCallerIdentity")
    actions.add("pricing:GetProducts")

    print(json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "CloudlensReadOnly",
            "Effect": "Allow",
            "Action": sorted(actions),
            "Resource": "*",
        }],
    }, indent=2))
    return 0


def _cmd_once(collector: Collector, args) -> int:
    started = time.monotonic()
    costs = collector.run_once()
    elapsed = time.monotonic() - started

    if args.json:
        print(json.dumps([{
            "account": c.account_name, "region": c.region, "service": c.service,
            "resource_type": c.resource_type, "resource": c.resource_id,
            "dimension": c.dimension, "tier": c.tier.value,
            "usd_per_hour": round(c.usd_per_hour, 8),
            "usd_per_month": round(c.usd_per_hour * 730, 4),
        } for c in sorted(costs, key=lambda c: -c.usd_per_hour)], indent=2))
        return 0

    if not costs:
        print("No costs found. Check credentials, regions, and that the role has the "
              "permissions from `cloudlens iam-policy`.")
        return 1

    # Roll the per-dimension rows up to one line per resource, which is the view you
    # actually want when asking "which Lambda function".
    rolled: dict[tuple, float] = defaultdict(float)
    tiers: dict[tuple, str] = {}
    for c in costs:
        key = (c.account_name, c.region, c.service, c.resource_id)
        rolled[key] += c.usd_per_hour
        tiers[key] = c.tier.value

    ranked = sorted(rolled.items(), key=lambda kv: -kv[1])[: args.top]
    total = sum(rolled.values())

    print(f"\n{len(rolled)} resources, {elapsed:.1f}s, "
          f"${total:.4f}/hr  (~${total * 730:,.2f}/month at this rate)\n")
    print(f"{'ACCOUNT':<14} {'REGION':<14} {'SERVICE':<18} {'RESOURCE':<44} "
          f"{'$/HOUR':>10} {'$/MONTH':>11}  TIER")
    print("-" * 132)
    for (account, region, service, resource), rate in ranked:
        name = resource if len(resource) <= 44 else "..." + resource[-41:]
        print(f"{account[:14]:<14} {region:<14} {service:<18} {name:<44} "
              f"{rate:>10.5f} {rate * 730:>11.2f}  {tiers[(account, region, service, resource)]}")
    return 0


def _cmd_run(collector: Collector, cost_registry: CostRegistry, config: Config) -> int:
    start_http_server(config.port, registry=build_registry(cost_registry))
    logging.getLogger(__name__).info(
        "serving metrics on :%d/metrics", config.port
    )
    collector.start()

    stop = False

    def handle(_sig, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, handle)
    signal.signal(signal.SIGTERM, handle)
    while not stop:
        time.sleep(1)

    logging.getLogger(__name__).info("shutting down")
    collector.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
