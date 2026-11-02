import time

import pytest
from botocore.stub import Stubber

from cloudlens import paths, sso


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDLENS_HOME", str(tmp_path))
    paths.ensure()
    return tmp_path


def _stub(portal, service):
    client = portal._session.client(service, region_name=portal.region)
    portal._session.client = lambda *a, **k: client   # hand the same stubbed client back
    return client


def test_device_login_discovery_and_role_credentials(home):
    p = sso.Portal("main", "https://x.awsapps.com/start", "ap-south-1")
    oidc = p._session.client("sso-oidc", region_name="ap-south-1")
    portal_api = p._session.client("sso", region_name="ap-south-1")
    p._oidc, p._sso = (lambda: oidc), (lambda: portal_api)

    with Stubber(oidc) as o:
        o.add_response("register_client", {"clientId": "cid", "clientSecret": "sec",
                                           "clientSecretExpiresAt": int(time.time()) + 86400})
        o.add_response("start_device_authorization", {
            "deviceCode": "dev", "userCode": "ABCD-EFGH", "verificationUri": "https://v",
            "verificationUriComplete": "https://v?code=ABCD", "expiresIn": 600, "interval": 1})
        login = p.start_login()
        o.add_client_error("create_token", "AuthorizationPendingException")
        assert p.poll(login) is False
        o.add_response("create_token", {"accessToken": "tok", "expiresIn": 28800, "tokenType": "Bearer"})
        assert p.poll(login) is True

    token_file = home / "sso" / "main.json"
    assert oct(token_file.stat().st_mode & 0o777) == "0o600"
    assert p.logged_in()

    with Stubber(portal_api) as s:
        s.add_response("list_accounts", {"accountList": [{"accountId": "111111111111", "accountName": "prod",
                                                          "emailAddress": "a@example.com"}]})
        s.add_response("list_account_roles", {"roleList": [{"roleName": "AdministratorAccess"},
                                                            {"roleName": "ReadOnlyAccess"}]})
        accounts = p.discover()
        assert accounts == [{"account_id": "111111111111", "name": "prod", "email": "a@example.com",
                             "roles": ["AdministratorAccess", "ReadOnlyAccess"]}]
        s.add_response("get_role_credentials", {"roleCredentials": {
            "accessKeyId": "AK", "secretAccessKey": "SK", "sessionToken": "ST",
            "expiration": int((time.time() + 3600) * 1000)}})
        session, expires = sso.SSOSource(p, "111111111111", "ReadOnlyAccess").session()
        assert session.get_credentials().access_key == "AK"


def test_expired_token_requires_login(home):
    p = sso.Portal("main", "https://x.awsapps.com/start", "ap-south-1")
    sso._write_private(home / "sso" / "main.json", {"accessToken": "t", "expiresAt": time.time() - 10})
    assert not p.logged_in()
    with pytest.raises(sso.LoginRequired):
        p.access_token()


def test_least_privileged_role_is_default():
    from cloudlens.store import pick_role
    assert pick_role(["AdministratorAccess", "ReadOnlyAccess"]) == "ReadOnlyAccess"
    assert pick_role(["AdministratorAccess", "DevPowerUser"]) == "DevPowerUser"
    assert pick_role(["AdministratorAccess"]) == "AdministratorAccess"
