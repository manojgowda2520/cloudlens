import boto3
import botocore.session
import pytest
from botocore.stub import Stubber

from cloudlens import guard


def test_reads_allowed_and_writes_refused_across_every_service_model():
    """Walk every operation of every service botocore knows. Anything that is not a
    read verb (or a reviewed exception) must be refused - the guard is an allowlist."""
    session = botocore.session.get_session()
    checked = 0
    for service in session.get_available_services():
        model = session.get_service_model(service)
        name = model.service_name
        for op in model.operation_names:
            checked += 1
            allowed = guard.is_allowed(name, op)
            if allowed and name not in guard.ALLOWED_SERVICES:
                assert op.startswith(guard.READ_PREFIXES) or (name, op) in guard.EXTRA_ALLOWED, (name, op)
            for verb in ("Create", "Delete", "Put", "Update", "Modify", "Attach", "Detach", "Terminate",
                         "Stop", "Start", "Run", "Invoke", "Send", "Publish", "Authorize", "Revoke", "Tag",
                         "Untag", "Enable", "Disable", "Reboot", "Restore", "Copy", "Import", "Associate"):
                if op.startswith(verb) and name not in guard.ALLOWED_SERVICES:
                    assert not allowed, (name, op)
    assert checked > 10000


@pytest.mark.parametrize("service,op", [
    ("s3", "GetObject"), ("secretsmanager", "GetSecretValue"), ("ssm", "GetParameter"),
    ("lambda", "GetFunction"), ("dynamodb", "GetItem"), ("ec2", "GetPasswordData"),
    ("logs", "GetLogEvents"), ("sts", "GetSessionToken"), ("ecr", "GetAuthorizationToken"),
])
def test_data_plane_reads_refused(service, op):
    assert not guard.is_allowed(service, op)


def test_guard_blocks_before_signing_and_audits(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "x")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "x")
    rows = []
    audit = guard.AuditLog(sink=rows.extend, batch=1)
    s = guard.protect(boto3.Session(region_name="us-east-1"), account="111111111111", audit=audit)
    ec2 = s.client("ec2", endpoint_url="http://127.0.0.1:9")   # unreachable: nothing may get out
    with pytest.raises(guard.WriteBlocked):
        ec2.terminate_instances(InstanceIds=["i-1"])
    with Stubber(ec2) as stub:
        stub.add_response("describe_regions", {"Regions": []})
        ec2.describe_regions()
    audit.flush()
    outcomes = [(r[4], r[5], r[6]) for r in rows]
    assert ("ec2", "TerminateInstances", "blocked") in outcomes
    assert ("ec2", "DescribeRegions", "ok") in outcomes
    assert audit.blocked == 1


def test_protect_is_idempotent():
    s = boto3.Session(region_name="us-east-1")
    assert guard.protect(guard.protect(s)) is s
