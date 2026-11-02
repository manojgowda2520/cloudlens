"""Tests for the part that is easy to get quietly wrong: turning a rate into a total."""
from __future__ import annotations

import time

import pytest

from cloudlens.cost.exporter import OTHER, CostRegistry
from cloudlens.cost.models import ResourceCost, Tier


def cost(resource_id: str, rate: float, *, service="lambda", region="us-east-1",
         dimension="duration", account="111111111111") -> ResourceCost:
    return ResourceCost(
        account_id=account, account_name="prod", region=region, service=service,
        resource_type="function", resource_id=resource_id, usd_per_hour=rate,
        tier=Tier.REALTIME, dimension=dimension,
    )


def rates_by_resource(reg: CostRegistry) -> dict[str, float]:
    idx = reg._labels.index("resource_id")
    return {key[idx]: value for key, value in reg._rates.items()}


def totals_by_resource(reg: CostRegistry) -> dict[str, float]:
    idx = reg._labels.index("resource_id")
    return {key[idx]: value for key, value in reg._totals.items()}


def test_first_update_records_rate_but_no_accrual():
    reg = CostRegistry()
    reg.update([cost("api-handler", 1.0)])

    assert rates_by_resource(reg)["api-handler"] == 1.0
    # Nothing has elapsed yet, so nothing has been spent yet.
    assert totals_by_resource(reg)["api-handler"] == 0.0


def test_total_integrates_the_previous_rate(monkeypatch):
    """The interval that just elapsed was spent at the OLD rate, not the new one."""
    reg = CostRegistry()
    clock = [1000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])

    reg.update([cost("api-handler", 3600.0)])   # $3600/hr == $1/second
    clock[0] += 10                              # ten seconds pass
    reg.update([cost("api-handler", 7200.0)])   # rate doubles

    # Ten seconds at the original $3600/hr is $10 - the doubling must not apply
    # retroactively.
    assert totals_by_resource(reg)["api-handler"] == pytest.approx(10.0)


def test_missed_scrape_does_not_double_count(monkeypatch):
    reg = CostRegistry()
    clock = [1000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])

    reg.update([cost("api-handler", 3600.0)])
    clock[0] += 30
    reg.update([cost("api-handler", 3600.0)])
    clock[0] += 30
    reg.update([cost("api-handler", 3600.0)])

    # One 60s gap or two 30s gaps must accrue the same $60.
    assert totals_by_resource(reg)["api-handler"] == pytest.approx(60.0)


def test_vanished_resource_drops_to_zero_rate():
    reg = CostRegistry()
    reg.update([cost("a", 1.0), cost("b", 2.0)])
    reg.update([cost("a", 1.0)])   # b was deleted

    rates = rates_by_resource(reg)
    assert rates["a"] == 1.0
    assert rates["b"] == 0.0, "a deleted resource must not keep reporting its old rate"


def test_empty_pass_with_declared_group_zeroes_the_service():
    """A service whose last resource is gone should fall to zero immediately."""
    reg = CostRegistry()
    reg.update([cost("only-one", 5.0)])
    reg.update([], groups=[("111111111111", "us-east-1", "lambda")])

    assert rates_by_resource(reg)["only-one"] == 0.0


def test_unrelated_service_is_untouched_by_a_partial_pass():
    reg = CostRegistry()
    reg.update([cost("fn", 1.0), cost("i-abc", 2.0, service="ec2",
                                      dimension="compute")])
    reg.update([cost("fn", 1.5)])   # only the lambda estimator reported

    rates = rates_by_resource(reg)
    assert rates["fn"] == 1.5
    assert rates["i-abc"] == 2.0, "an EC2 series must survive a Lambda-only pass"


def test_min_rate_floor_folds_noise_into_other():
    reg = CostRegistry(min_usd_per_hour=0.01)
    reg.update([cost("big", 1.0), cost("dust-1", 0.001), cost("dust-2", 0.002)])

    rates = rates_by_resource(reg)
    assert rates["big"] == 1.0
    assert "dust-1" not in rates
    # The money is not lost, just aggregated.
    assert rates[OTHER] == pytest.approx(0.003)


def test_top_n_cap_preserves_the_total():
    reg = CostRegistry(top_n=3)
    reg.update([cost(f"fn-{i}", float(i)) for i in range(1, 11)])

    rates = rates_by_resource(reg)
    named = {k: v for k, v in rates.items() if k != OTHER}
    assert len(named) == 3
    assert set(named) == {"fn-10", "fn-9", "fn-8"}, "must keep the most expensive"
    assert sum(rates.values()) == pytest.approx(sum(range(1, 11)))


def test_tag_keys_become_labels():
    reg = CostRegistry(tag_keys=("Team", "cost-center"))
    assert "tag_team" in reg._labels
    assert "tag_cost_center" in reg._labels, "label names must be Prometheus-safe"


def test_metric_names_and_families():
    reg = CostRegistry()
    reg.update([cost("fn", 1.0)])
    names = {m.name for m in reg.collect()}

    assert "cloudlens_resource_usd_per_hour" in names
    assert "cloudlens_resource_usd" in names   # exposed as ..._total by the client
    assert "cloudlens_estimate_drift_ratio" in names
