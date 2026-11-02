from cloudlens import secrets


def test_scrub_redacts_every_value_and_names_the_risky_ones():
    env = {"DB_PASSWORD": "s3cr3t-value!", "STAGE": "prod", "AWS_KEY": "AKIAIOSFODNN7EXAMPLE",
           "SECRET_ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:x", "TOKEN": ""}
    redacted, hits = secrets.scrub_env(env)
    assert set(redacted.values()) == {secrets.REDACTED}
    kinds = {h["name"]: h["kind"] for h in hits}
    assert kinds == {"DB_PASSWORD": "sensitive-name", "AWS_KEY": "aws-access-key-id"}


def test_patterns():
    assert secrets.classify("X", "postgres://app:pa55word@db:5432/x") == "connection-string-password"
    assert secrets.classify("X", "-----BEGIN RSA PRIVATE KEY-----\nabc") == "private-key"
    assert secrets.classify("LOG_LEVEL", "debug") == ""
    assert secrets.classify("API_KEY", "{{resolve:secretsmanager:x}}") == ""
