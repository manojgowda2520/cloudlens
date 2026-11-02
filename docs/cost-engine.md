# Cost engine

Real-time, **per-resource** AWS cost attribution, exported to Prometheus and Grafana.

Not "AWS spent $4,102 on Lambda last month." Rather: **`checkout-api` is burning
$16.67/hour right now, and 94% of that is duration, not requests.**

```
ACCOUNT        REGION         SERVICE            RESOURCE                      $/HOUR      $/MONTH  TIER
data-prod      ap-south-1     ec2                i-0f3a91c4e8b2d7a10          0.38400       280.32  inventory
data-prod      ap-south-1     cloudwatch_logs    /aws/lambda/checkout-api     0.21050       153.67  realtime
platform-prod  us-east-1      lambda             checkout-api                 0.16670       121.69  realtime
platform-prod  us-east-1      natgateway         nat-04c1f8e2a9b6d3e57        0.09220        67.31  realtime
```

---

## Why this exists

AWS has no real-time cost API, and no per-resource one either.

| Source | Lag | Granularity |
|---|---|---|
| Cost Explorer | 6–24 hours | Service. Resource-level for EC2 only, opt-in, extra cost |
| Cost and Usage Report | 1–24 hours | Line item, but delivered to S3 as a batch file |
| Budgets / alerts | hours to days | Account or tag |

By the time any of them tells you a Lambda has been retry-looping, it has been looping
for a day.

cloudlens takes a different route: it **derives** cost instead of reading it. Lambda
publishes `Invocations` and `Duration` per function as 1-minute CloudWatch metrics.
Multiply by the GB-second and per-request rates from the AWS Pricing API and you have
per-function spend, accurate to within rounding, roughly two minutes behind real time.
The same trick works for DynamoDB capacity units, SQS requests, NAT gateway bytes,
CloudWatch log ingestion, and ALB LCUs.

Then Cost Explorer is polled hourly — not as the primary signal, but as the yardstick
that tells you how far the derived numbers have drifted from what AWS actually billed.

---

## Coverage: two tiers, no gaps

AWS ships 200+ services with unrelated pricing dimensions, and most publish no
per-resource usage metric at all. Pretending otherwise would mean quietly dropping
spend on the floor. So coverage is explicitly tiered, and the tier is a **metric label**
you can filter and chart on.

**Tier 1 — 26 estimators with per-resource attribution:**

| | |
|---|---|
| **Realtime** (CloudWatch-derived, ~60s) | `lambda` · `dynamodb` · `sqs` · `sns` · `apigateway` · `kinesis` · `cloudwatch_logs` · `natgateway` · `elb` · `cloudfront` |
| **Inventory** (config-derived, ~5min) | `ec2` · `ebs` · `rds` · `s3` · `efs` · `ecr` · `fargate` · `eks` · `elasticache` · `opensearch` · `redshift` · `route53` · `vpc_endpoint` · `secretsmanager` · `kms` |

*Realtime* means the cost comes from measured usage. *Inventory* means the resource is
billed for existing, so the describe call **is** the measurement — an `m5.xlarge` costs
the same whether it is at 3% or 93% CPU.

**Tier 2 — everything else.** The `cost_explorer` estimator sweeps up every remaining
service at service granularity from the billing system. Slower and coarser, but it
means the total is complete. It is labelled `tier="billing"` and
`dimension="fallback_only"` so you can see exactly which dollars you cannot drill into.

> **Totals:** derived and billing tiers overlap by design, so adding them double-counts.
> The correct total is `tier != "billing"` **plus** `tier = "billing" AND dimension =
> "fallback_only"`. Every dashboard panel already does this.

---

## Quick start

```bash
pip install -r requirements.txt
```

Point it at an account and look at one sweep before committing to any infrastructure:

```bash
cp config.example.yaml config.yaml && python -m cloudlens once -c config.yaml
```

Bring up the full stack — collector, Prometheus, Grafana with both dashboards
provisioned:

```bash
docker compose up -d
```

Grafana lands on <http://localhost:3000> (`admin` / `$GRAFANA_PASSWORD`, default
`admin`), raw metrics on <http://localhost:9101/metrics>.

---

## Multi-account setup

The collector runs in one account and assumes a read-only role in each member account.

Deploy the role across the organisation as a CloudFormation **StackSet**:

```bash
aws cloudformation create-stack-set \
  --stack-set-name cloudlens-reader \
  --template-body file://deploy/iam/member-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=CollectorAccountId,ParameterValue=111111111111 \
               ParameterKey=ExternalId,ParameterValue="$CLOUDLENS_EXTERNAL_ID"
```

Then list the accounts in `config.yaml`:

```yaml
accounts:
  - account_id: "111111111111"
    name: platform-prod          # collector's own account, ambient credentials
  - account_id: "222222222222"
    name: data-prod
    role_arn: arn:aws:iam::222222222222:role/CloudlensReader
    external_id: ${CLOUDLENS_EXTERNAL_ID}
```

The role is read-only by construction: it can enumerate resources and read metrics, and
cannot read object contents, secret values, or key material. `cloudlens iam-policy`
prints the minimal policy for exactly the estimators you have enabled — useful for
trimming it further.

The `ExternalId` is not decoration. Without it, anyone who guesses your collector's role
ARN can assume into your accounts; it is the standard guard against the confused-deputy
problem.

---

## Metrics

```
cloudlens_resource_usd_per_hour{account_id, account_name, region, service,
                               resource_type, resource_id, dimension, tier, tag_*}
cloudlens_resource_usd_total{...}          # same labels, integrated
```

The gauge answers *"what is this costing me right now"*; the counter answers *"what has
it cost since the collector started"*. The counter is integrated from the gauge rather
than read from AWS, so a missed scrape loses a little accuracy but **never
double-counts**, and `increase()` works over any window.

`dimension` splits one resource into what you are actually paying for — Lambda
`duration` vs `requests`, EBS `storage` vs `iops` vs `throughput`, CloudWatch Logs
`ingestion` vs `storage`. This is usually where the surprise is: log *ingestion* costs
about 17× what storing that same gigabyte for a month costs.

Useful queries:

```promql
# Which Lambda function, right now
topk(10, sum by (resource_id) (cloudlens_resource_usd_per_hour{service="lambda"}))

# What did it actually cost overnight
sum by (resource_id) (increase(cloudlens_resource_usd_total{service="lambda"}[8h]))

# Anything that got 3x more expensive in the last hour
cloudlens_resource_usd_per_hour
  > 3 * (cloudlens_resource_usd_per_hour offset 1h) > 0.10

# Spend with no owner (requires tag_keys: [Team])
sum(cloudlens_resource_usd_per_hour{tag_team=""}) * 730
```

Operational metrics — collection duration, error rate, staleness, Pricing API cache hit
rate, and estimate-vs-actual drift — are on the **Collector Health & Accuracy**
dashboard. Alert rules for spend spikes and collector failure ship in
`deploy/alerts.yml`.

---

## Accuracy: what it gets right and wrong

**Everything is public on-demand list price.** Savings Plans, Reserved Instances, EDP
discounts, private pricing, and credits are invisible to the Pricing API. On a fleet
with heavy RI coverage, EC2 will read high — sometimes 40% high.

This is measured rather than hidden. `cloudlens_estimate_drift_ratio` divides the derived
run-rate by the Cost Explorer actual for the same service:

- **~1.0** — the model matches the invoice.
- **stable 0.6** — you have a Savings Plan. Expected, and the ratio itself tells you
  your effective discount.
- **suddenly moves** — a pricing assumption broke. Worth a look.

Also worth knowing:

- **Lambda** ignores provisioned concurrency, which bills even at zero invocations.
- **S3** storage moves once a day (`BucketSizeBytes` is a daily metric) and request
  charges need per-bucket request metrics enabled, which is itself a paid feature.
- **ECR** counts shared layers once per image, so repos with many tags of one build read
  high.
- **Data transfer** other than NAT and CloudFront is not resource-attributable and lands
  in the Cost Explorer fallback.
- **Aurora** bills storage and I/O at cluster level; only instance-hours are attributed.

When the Pricing API returns nothing for a lookup, a pinned us-east-1 list price stands
in and `cloudlens_pricing_fallback_total` increments — so silently-wrong pricing shows up
as a metric rather than as a number you trust by mistake.

---

## Cost and scale of running it

- **Cost Explorer** is $0.01 per call. At the default hourly cadence that is ~$7/month
  across ten accounts. Everything else — CloudWatch `GetMetricData`, describe calls, the
  Pricing API — is free.
- **API volume** is the real constraint. A sweep is `accounts × regions × estimators`
  tasks, fanned out across a thread pool. CloudWatch reads are batched up to 450 queries
  per `GetMetricData` call, and prices are cached on disk, so a warm collector makes
  zero Pricing API calls.
- **Cardinality** is capped in the collector, not in Prometheus. Resources below
  `min_usd_per_hour`, and everything past `top_n` within a
  (account, region, service, dimension) group, fold into a single `__other__` series —
  so the totals stay correct while the series count stays bounded. Prefer raising
  `min_usd_per_hour` over dropping series at ingest, which loses the money silently.

Mount the pricing cache as a volume. Without it every restart replays a few hundred
throttled Pricing API calls.

---

## Adding an estimator

Drop a class in `cloudlens/estimators/`, decorate it, and it is picked up by the
registry, the scheduler, the IAM policy generator, and the dashboards automatically.

```python
@register
class MyServiceEstimator(Estimator):
    name = "myservice"
    tier = Tier.REALTIME
    cadence = "realtime"
    required_actions = ("myservice:ListThings", "cloudwatch:GetMetricData")

    def collect(self, ctx: Context) -> Iterable[ResourceCost]:
        things = safe(lambda: list(ctx.paginate("myservice", "list_things", "Things")),
                      [], "myservice:ListThings")
        usage = ctx.metrics().read([
            MetricQuery("u::" + t["Id"], "AWS/MyService", "Requests", {"ThingId": t["Id"]})
            for t in things
        ])
        rate = ctx.pricing.price("AWSMyService", {"group": "Requests"},
                                 region=ctx.region, unit_hint="Requests")
        for t in things:
            per_hour = usage.get("u::" + t["Id"], 0.0)
            if per_hour:
                yield ctx.cost(service="myservice", resource_type="thing",
                               resource_id=t["Id"], usd_per_hour=per_hour * rate,
                               tier=Tier.REALTIME, dimension="requests")
```

Two rules that keep the whole thing honest:

1. **Emit a rate, never an accumulated amount.** The exporter integrates. Emitting
   totals makes missed scrapes double-count.
2. **Wrap every AWS call in `safe()`.** One denied permission in one region must not
   take down the sweep — partial cost data beats none.

---

## Tests

```bash
python -m pytest -q
```

24 tests, no AWS account or network required. They cover the arithmetic that is easy to
get quietly wrong: rate-to-total integration across missed scrapes, `Sum`-to-hourly
normalisation for sparsely-reported metrics, the gp3 free-IOPS baseline, ARM vs x86
Lambda rates, and cardinality caps preserving totals.

---

## Layout

```
cloudlens/
  accounts.py       cross-account role assumption, credential refresh
  pricing.py        AWS Pricing API client, disk-cached
  cloudwatch.py     batched GetMetricData, Sum -> hourly rate
  base.py           estimator contract and registry
  estimators/       one module per service group
  exporter.py       Prometheus exposition, integration, cardinality caps
  collector.py      per-cadence scheduling, fan-out, reconciliation
deploy/
  iam/              CloudFormation StackSet for the member-account role
  grafana/          provisioned datasource and both dashboards
  alerts.yml        spend-spike and collector-health rules
```
