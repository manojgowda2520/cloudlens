"""End-to-end scan against moto: collectors -> store -> checks, no real AWS."""
import io
import json
import zipfile

import boto3
import pytest
from moto import mock_aws

from cloudlens import guard
from cloudlens.accounts import AccountSession
from cloudlens.config import AccountConfig
from cloudlens.scan import Scanner
from cloudlens.store import Store

ACCOUNT = "123456789012"   # moto's default account


def _zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", "def handler(e, c):\n    return 1\n")
    return buf.getvalue()


@pytest.fixture
def aws(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": "us-east-1", "MOTO_IAM_LOAD_MANAGED_POLICIES": "true"}.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        yield


def _seed():
    iam = boto3.client("iam")
    iam.create_user(UserName="alice")
    iam.attach_user_policy(UserName="alice", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.create_access_key(UserName="alice")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName="fn-role", AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    iam.attach_role_policy(RoleName="fn-role", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    open_trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName="anyone", AssumeRolePolicyDocument=json.dumps(open_trust))

    s3 = boto3.client("s3")
    s3.create_bucket(Bucket="public-site")
    s3.put_bucket_policy(Bucket="public-site", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::public-site/*"}]}))

    ec2 = boto3.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="ssh-open", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=100, VolumeType="gp3")

    boto3.client("lambda").create_function(
        FunctionName="leaky", Runtime="python3.8", Role=role["Arn"], Handler="index.handler",
        Code={"ZipFile": _zip()},
        Environment={"Variables": {"DB_PASSWORD": "hunter2hunter2", "MODE": "prod"}})


def test_scan_end_to_end(aws, tmp_path):
    _seed()
    store = Store(tmp_path / "t.db")
    audit = guard.AuditLog(sink=store.record_api_calls)
    scanner = Scanner(store, {}, audit, workers=4)
    session = AccountSession(AccountConfig(account_id=ACCOUNT, name="test"), audit=audit)
    acct = {"account_id": ACCOUNT, "portal_id": "p", "name": "test", "regions": '["us-east-1"]'}
    scanner.regions_for = lambda a, s, e: ["us-east-1"]
    scanner.portals = {"p": type("P", (), {"region": "us-east-1"})()}

    scan_id = store.start_scan(["inventory", "security"])
    errors = []
    scanner._inventory(scan_id, {ACCOUNT: (acct, session)}, errors)
    scanner._security(scan_id, [ACCOUNT])
    audit.flush()
    # The only expected failures are moto gaps, never cloudlens errors.
    assert [e for e in errors if "Not yet implemented" not in e[3]] == []

    types = {(r["service"], r["type"]) for r in store.resources(scan_id)}
    for t in [("iam", "user"), ("iam", "role"), ("s3", "bucket"), ("ec2", "security-group"),
              ("lambda", "function"), ("ec2", "volume"), ("account", "account")]:
        assert t in types, t

    found = {(f["check_id"], f["arn"].rsplit(":", 1)[-1].rsplit("/", 1)[-1])
             for f in store.q("SELECT * FROM findings WHERE scan_id=?", (scan_id,))}
    assert ("IAM-06", "alice") in found
    assert ("LMB-01", "leaky") in found
    assert ("LMB-05", "leaky") in found
    assert ("LMB-06", "leaky") in found
    assert ("IAM-08", "anyone") in found
    assert any(c == "S3-01" for c, _ in found)
    assert any(c == "NET-01" for c, _ in found)

    # Secrets never reach the database.
    blob = json.dumps([dict(r) for r in store.resources(scan_id)])
    assert "hunter2" not in blob
    # Nothing but reads went out.
    assert store.one("SELECT COUNT(*) n FROM api_calls WHERE outcome='blocked'")["n"] == 0
    assert store.one("SELECT COUNT(*) n FROM api_calls")["n"] > 20
