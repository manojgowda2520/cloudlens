# cloudlens

One local dashboard for every AWS account you can reach: **what's running, what it costs, and what's insecure**.

> **Status: early development.** Today cloudlens ships the cost engine (per-resource,
> near-real-time cost exported to Prometheus/Grafana — see
> [docs/cost-engine.md](docs/cost-engine.md)). SSO portals, inventory, security checks
> and the web UI are being built next. The full design is in [SPEC.md](SPEC.md).

## What it will do

- **Many SSO portals, many accounts.** Add each IAM Identity Center start URL once; cloudlens
  discovers every account behind it.
- **Inventory** of every resource in every enabled region, searchable across accounts.
- **Security posture**: about 45 checks across Lambda, IAM, S3, network, domains/certificates,
  logging and data protection, each with evidence and a fix.
- **Cost**: per-account and per-service spend, forecast, top resources, waste hints.
- **History**: every scan is kept, so you can diff "what changed since last week".

## Safety model

cloudlens is read-only by construction, even when the credentials behind it are admin:

- every AWS call passes a guard that only allows `Describe*`/`List*`/`Get*`-style
  operations and blocks data-plane reads (S3 objects, secret values, table items);
- secret-looking environment values are detected in memory and never stored;
- every call is written to a local audit log;
- all state lives in `~/.cloudlens/` (owner-only), never in the repository.

## Quick start (cost engine)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
mkdir -p ~/.cloudlens && cp config.example.yaml ~/.cloudlens/config.yaml
.venv/bin/python -m cloudlens once
```

## Layout

```
cloudlens/
  paths.py      state directory (~/.cloudlens, override with CLOUDLENS_HOME)
  accounts.py   per-account boto3 sessions
  config.py     YAML config
  cost/         estimators, pricing, Cost Explorer, Prometheus exporter
  cli.py        `cloudlens` command
deploy/         Prometheus, Grafana dashboards, IAM role template
```

## Development

```bash
.venv/bin/pip install pytest moto
.venv/bin/python -m pytest
```
