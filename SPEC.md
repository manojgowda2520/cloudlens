# cloudlens — Spec v0.1

**One local dashboard for every AWS account I can reach: what's running, what it costs, what's insecure.**

Status: M0–M5 implemented 2026-11-02 (not yet run against real accounts) · Owner: Manoj Kumar K
Grows out of `costlens` (cost estimators, multi-account sessions, Prometheus/Grafana), which is kept and extended rather than rewritten.

---

## 1. Goals

1. **One place for all accounts.** Several AWS IAM Identity Center (SSO) portals, each with several accounts, all shown together.
2. **Inventory.** Every resource, every enabled region, every account, searchable.
3. **Security posture.** Concrete findings with severity and a fix note: Lambda, IAM, S3, network, domains/certs, logging.
4. **Cost.** Per-account and per-service spend, forecast, top resources. Near-real-time per-resource cost via the existing costlens estimators.
5. **Change over time.** Every scan is kept, so "what's new since last week" is a single click.
6. **Portfolio-grade.** Public repo, clean README, tests, CI, Docker, demo dataset for screenshots.

## 2. Non-goals (v1)

- **No writes to AWS, ever.** No auto-remediation, no "fix" buttons.
- Not multi-user, not hosted. Runs on my Mac, bound to `127.0.0.1`.
- Not a replacement for Security Hub / GuardDuty. If those are enabled, we read and show their findings, but we don't reimplement threat detection.
- No Azure/GCP.

## 3. Hard safety rules

The SSO role is **AdministratorAccess**, so safety is enforced in code, not by IAM.

| # | Rule | How |
|---|---|---|
| S1 | **Read-only allowlist** | A botocore `before-call` hook on every client. The operation name must start with `Describe`, `List`, `Get`, `BatchGet`, `Lookup`, `Search` or `Query`, or be on an explicit extras list. Anything else raises `WriteBlocked` before the request is signed. This is unit-tested against every write verb. |
| S2 | **No data-plane reads** | A denylist inside the allowed verbs. Blocked: `s3:GetObject*`, `secretsmanager:GetSecretValue`, `ssm:GetParameter*` with decryption, `kms:Decrypt`/`GenerateDataKey*`, `lambda:GetFunction` (it returns a code download URL; use `GetFunctionConfiguration`), `dynamodb:GetItem`/`Query`/`Scan`, `logs:GetLogEvents`/`FilterLogEvents`, `ecr:GetDownloadUrlForLayer`. We inspect configuration only, never customer data. |
| S3 | **Secrets are never stored** | Lambda/ECS environment values are pattern-checked in memory (AWS keys, private keys, `password=`, JWTs, high-entropy strings). Only the **variable name plus the matching pattern type** is saved, never the value. |
| S4 | **Audit log** | Every AWS call is appended to `api_calls` with time, portal, account, region, service, operation and outcome. A UI page shows it, and `cloudlens audit --writes` must always return zero rows. |
| S5 | **No company data in git** | All state lives in `~/.cloudlens/` (mode `0700`): the DB, the SSO token cache and config. The repo contains only `config.example.yaml` and a synthetic demo dataset. A pre-commit check rejects 12-digit account IDs except the documented fakes `111111111111`, `222222222222` and so on. |
| S6 | **Local only** | The web server binds `127.0.0.1`, no CORS, and every POST needs a CSRF token. |

## 4. Accounts and authentication

### 4.1 Model

```
Portal (one SSO start URL)        e.g. "Main portal", https://xxxx.awsapps.com/start, region ap-south-1
 └─ Account (discovered)          e.g. Prod 1234…, Dev 5678…
     └─ Role (picked once)        e.g. AdministratorAccess
```

Many portals, each with many accounts. The same account reached through two portals is de-duplicated by account ID, and the first portal wins.

### 4.2 Flow

1. **Add portal** (UI): nickname, start URL, SSO region.
2. The app runs the **OIDC device-authorization flow** itself (`sso-oidc:RegisterClient` → `StartDeviceAuthorization`) and opens the verification URL in the browser. I approve, then the app polls `CreateToken`.
3. The token is cached in `~/.cloudlens/sso/<portal>.json` (`0600`). If a refresh token is issued, it is used to renew silently. Otherwise the portal shows **"Re-login"** when the token expires (typically 8–12 h), and the other portals are unaffected.
4. **Discover:** `sso:ListAccounts` then `ListAccountRoles`. I tick the accounts to monitor and pick a role for each. The default is the least-privileged role available, e.g. ReadOnly over Admin.
5. **Credentials:** `sso:GetRoleCredentials` per account, cached until 5 minutes before expiry. This plugs into the existing `AccountSession`.
6. **Regions per account:** default is all regions where `ec2:DescribeRegions` reports opted-in. This can be narrowed per account to speed up scans.

### 4.3 Code change

`costlens.accounts.AccountSession` gets a pluggable **`CredentialSource`** with three implementations:
- `SSOSource` (new)
- `AssumeRoleSource` (today's STS behaviour, kept)
- `AmbientSource` (local profile or instance role)

The estimators don't change.

## 5. Scanning

**Scan:** one run over the selected accounts × regions × modules. It is triggered by the "Scan now" button, `cloudlens scan`, or an optional schedule (launchd, nightly).

| Module | What | Default cadence |
|---|---|---|
| `inventory` | Per-service collectors (§6), plus `resourcegroupstaggingapi:GetResources` as a catch-all for anything taggable we don't have a collector for | each scan |
| `security` | Checks (§7), run against the inventory just collected, plus a few direct API reads | each scan |
| `cost` | Cost Explorer daily by service and account, plus a month forecast. Cached for 24 h because each call costs $0.01. | once a day |
| `realtime-cost` | Existing costlens estimators → Prometheus exporter | optional, long-running `cloudlens collect` |

- **Concurrency:** a thread pool across account×region (default 16) with adaptive retries; the existing `BOTO_CONFIG` is reused.
- **Fault isolation:** the existing `safe()` wrapper is kept. A denied or failed call becomes a **scan error** row and shows in the UI as "partial coverage". It never shows silently as "0 resources".
- **Target time:** about 6 accounts × enabled regions in under 5 minutes.

## 6. Inventory — v1 collectors

Global: IAM (users, roles, policies, groups, access keys, credential report), Organizations (if readable), Route 53 domains and hosted zones/records, CloudFront, S3 buckets (with per-bucket config: policy, ACL, public-access block, encryption, versioning, logging).

Regional:

| Area | Services |
|---|---|
| Compute | EC2, EBS, AMIs, snapshots, Elastic IPs, Auto Scaling groups, **Lambda** (configuration, resource policy, URL config, layers, event sources), ECS, EKS, Lightsail |
| Data | RDS/Aurora, DynamoDB, ElastiCache, OpenSearch, Redshift, EFS |
| App | API Gateway (REST, HTTP, WS), SQS, SNS, EventBridge, Step Functions, Cognito user pools, AppSync, Amplify |
| Network | VPC, subnets, security groups, NACLs, NAT, IGW, VPC endpoints, load balancers + listeners |
| Security | KMS keys + policies, Secrets Manager (metadata only), ACM certificates, WAF web ACLs, GuardDuty status, Security Hub status, CloudTrail trails, Config recorder |
| Other | ECR repositories, CloudWatch log groups (retention, size), CloudFormation stacks, Backup plans |

Each resource is stored as `{arn, account, region, service, type, name, tags, created, raw_json}`. `raw_json` keeps the full describe output, so new checks can run on old scans.

## 7. Security checks — v1 (about 45)

Each check has an `id`, severity (Critical/High/Medium/Low/Info), title, affected ARN, evidence (the exact field that failed) and a remediation note. Severity follows common CIS/AWS FSBP practice. Mapping to CIS control IDs is shown where one exists.

**Lambda**
- `LMB-01` Execution role has `*:*` or AdministratorAccess. **Critical**
- `LMB-02` Execution role allows `iam:PassRole`, `iam:*` or `sts:AssumeRole` on `*`. **High**
- `LMB-03` Resource policy allows `Principal: *` without a `SourceArn`/`SourceAccount` condition. **High**
- `LMB-04` Function URL with `AuthType NONE`. **High**
- `LMB-05` Environment variable looks like a secret (S3 rule). **High**
- `LMB-06` Deprecated or soon-deprecated runtime. **Medium**
- `LMB-07` Environment not encrypted with a customer KMS key. **Low**
- `LMB-08` No DLQ / on-failure destination on async-invoked functions. **Low**
- `LMB-09` Zero invocations in 90 days (cleanup candidate). **Info**

**IAM**
- `IAM-01` Root has access keys. **Critical**
- `IAM-02` Root has no MFA. **Critical**
- `IAM-03` Console user without MFA. **High**
- `IAM-04` Access key older than 90 days. **Medium**
- `IAM-05` Access key unused for 90+ days. **Medium**
- `IAM-06` User with inline/attached admin. **High**
- `IAM-07` Customer policy with `Action:*` + `Resource:*`. **High**
- `IAM-08` Role trust policy allows `Principal: *` or any AWS account without `ExternalId`. **Critical**
- `IAM-09` Role unused for 90+ days. **Low**
- `IAM-10` Weak or missing account password policy. **Medium**

**S3**
- `S3-01` Bucket public via policy or ACL. **Critical**
- `S3-02` Account-level Block Public Access off. **High**
- `S3-03` Bucket-level Block Public Access off. **Medium**
- `S3-04` No default encryption. **Low** (AWS encrypts by default since 2023, so only flagged when explicitly disabled)
- `S3-05` Policy doesn't enforce TLS (`aws:SecureTransport`). **Medium**
- `S3-06` Versioning off on a bucket tagged prod. **Low**
- `S3-07` Bucket policy grants another account. **Info** (reported for review, not judged)

**Network**
- `NET-01` Security group allows `0.0.0.0/0` or `::/0` on 22/3389. **Critical**
- `NET-02` Same, on database ports (3306/5432/1433/27017/6379/9200). **Critical**
- `NET-03` Same, on all ports. **Critical**
- `NET-04` Default security group has rules. **Medium**
- `NET-05` VPC flow logs off. **Medium**
- `NET-06` RDS publicly accessible. **High**
- `NET-07` EC2 with public IP + IMDSv1 allowed. **High**
- `NET-08` Load balancer listener on HTTP without redirect, or an outdated TLS policy. **Medium**

**Domains & certificates**
- `DNS-01` Route 53 domain expires within 30 days, or auto-renew is off. **High**
- `DNS-02` Domain transfer lock off. **Medium**
- `DNS-03` Dangling record: CNAME/ALIAS to a missing S3 bucket, CloudFront distribution, Elastic Beanstalk env or released EIP (takeover risk). **Critical**
- `DNS-04` ACM certificate expires within 30 days, or renewal is failing. **High**
- `DNS-05` CloudFront allows HTTP, or a TLS minimum below 1.2. **Medium**

**Logging & detection**
- `LOG-01` No multi-region CloudTrail. **High**
- `LOG-02` GuardDuty off in a region with resources. **Medium**
- `LOG-03` Security Hub off. **Info**
- `LOG-04` Log groups with no retention (cost and hygiene). **Low**

**Data**
- `DAT-01` RDS/DynamoDB/EBS unencrypted. **High**
- `DAT-02` RDS/EBS snapshot shared publicly. **Critical**
- `DAT-03` RDS with no backups, or deletion protection off on prod. **Medium**
- `DAT-04` KMS key policy allows `Principal: *` without conditions. **High**
- `DAT-05` Secrets Manager secret not rotated in 180 days. **Low**

**Imported:** if GuardDuty or Security Hub is on, their active findings are pulled in and labelled `source=aws`.

Findings can be **suppressed** with a reason (e.g. "public by design: static site"). Suppressions survive rescans.

## 8. Cost

- **From Cost Explorer (daily):** month-to-date spend, forecast and last month per account; spend by service; a 30-day daily trend.
- **Top resources:** the existing costlens estimators give $/hour per resource, joined to the inventory so each resource page shows "≈ $X/month".
- **Waste hints:** unattached EBS volumes, idle EIPs, old snapshots, stopped instances still paying for EBS, empty load balancers, Lambdas idle for 90 days. Each shows an estimated $/month saving.
- **Grafana (optional):** `docker compose up` brings back the existing Prometheus + Grafana dashboards for live cost charts. The web UI links to them.

## 9. UI

Local web app at `http://127.0.0.1:8080`.

| Page | Contents |
|---|---|
| **Overview** | One card per account: portal, MTD spend + forecast, Critical/High counts, resource count, last scan, coverage warnings. Totals across all accounts at the top. |
| **Portals** | Add / re-login / remove portals; pick accounts and roles; per-account regions. |
| **Inventory** | One table across everything; filter by portal/account/region/service/tag; full-text search; resource detail with raw JSON, related findings and cost. |
| **Findings** | Grouped by severity, check or account; suppress with a reason; "new since last scan" filter. |
| **Cost** | By account and service, trend chart, top resources, waste list. |
| **Scans** | History, duration, errors; diff between two scans (resources added/removed, findings opened/closed). |
| **Audit** | AWS call log with a writes counter (always 0). |
| **Export** | Findings and inventory as CSV; a one-page HTML/PDF report per account. |

## 10. Architecture

```
cloudlens/
  auth/        sso.py (device flow, token cache), sources.py (CredentialSource impls)
  guard.py     read-only allowlist/denylist hook + audit logger           (S1, S2, S4)
  inventory/   one module per service area, registry like the estimators
  checks/      one module per area, each check a small function over the inventory
  cost/        explorer.py (daily CE) + existing estimators/, pricing, exporter
  store/       SQLite schema + migrations, scan diffing
  web/         FastAPI app, Jinja templates + HTMX, Chart.js — no Node build step
  cli.py       cloudlens portal add | scan | serve | collect | audit | export
```

- **Stack:** Python 3.12, boto3, FastAPI, SQLite (WAL), HTMX. Optional Prometheus/Grafana via the existing Docker files.
- **SQLite tables:** `portals`, `accounts`, `scans`, `scan_errors`, `resources`, `findings`, `suppressions`, `cost_daily`, `api_calls`.

## 11. Quality and portfolio

- **Tests:** pytest + moto. The guard has its own exhaustive test (every known write operation must be blocked). Each check is tested with passing and failing fixtures.
- **CI:** GitHub Actions running lint (ruff), tests, a secret scan (gitleaks) and the account-ID check (S5).
- **Demo mode:** `cloudlens serve --demo` loads a synthetic dataset of three fake portals and eight fake accounts with realistic findings. All screenshots and the README use this, never real data.
- **README:** problem, architecture diagram, safety model (§3), screenshots, quick start.
- **Git:** new public repo `manojgowda2520/cloudlens`, author Manoj only, per the usual no-attribution rule.

## 12. Milestones

| # | Deliverable | Done when |
|---|---|---|
| **M0** | New repo, costlens code moved in and renamed, tests green, `~/.cloudlens` layout | `pytest` passes; costlens behaviour unchanged |
| **M1** | Guard + audit log; SSO portals (device flow, discovery, re-login); `CredentialSource` refactor | I add my real portals and see every account listed; the audit log shows only reads |
| **M2** | Inventory collectors + Inventory page + Overview cards | One scan across all accounts; I can search "lambda" and see every function |
| **M3** | Security checks + Findings page + suppressions | Findings appear across all accounts; I can spot-check five against the console |
| **M4** | Cost page (Cost Explorer daily + waste hints), estimator join, optional Grafana | MTD per account matches the Billing console within ±1% |
| **M5** | Scan history/diff, exports, demo dataset, README, CI | Public repo ready to put on the resume |

## 13. Decisions taken

1. Nightly scan: off by default. `cloudlens schedule` prints a launchd job to install by hand.
2. Role choice: the least-privileged role a portal offers is the default (ReadOnly before Admin); it can be changed per account.
3. The old `costlens` folder in the archive repo stays as it is.
4. Python 3.9+ is supported, so it runs on the macOS system Python; CI tests 3.9 and 3.12.
5. The UI loads no third-party scripts or fonts (charts are server-rendered SVG), so it works offline and the CSP is `'self'` only.
