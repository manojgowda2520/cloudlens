"""IAM Identity Center (SSO) sign-in, account discovery and role credentials.

Sign-in uses the OAuth device-authorization flow, the same one `aws sso login` uses:
register a public client, ask for a device code, send the user to a verification URL,
poll for the token. cloudlens runs the flow itself so there is no dependency on the
AWS CLI or ~/.aws/config, and so each portal's token is kept apart from the user's
own CLI sessions.

Token files live in ~/.cloudlens/sso/<portal>.json, mode 0600. A token is a bearer
credential for every account behind the portal - it is never logged or displayed.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import boto3
from botocore.config import Config as BotoConfig

from . import guard, paths

log = logging.getLogger(__name__)

CLIENT_NAME = "cloudlens"
SCOPES = ["sso:account:access"]
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
_SKEW = 300  # treat a token as expired five minutes early

_BOTO = BotoConfig(retries={"max_attempts": 6, "mode": "adaptive"}, connect_timeout=5, read_timeout=30)


class LoginRequired(Exception):
    """The portal has no valid token; the user must sign in again."""


def slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "portal"


def _plain_session(audit: Optional[guard.AuditLog] = None, portal: str = "") -> boto3.Session:
    # A session with no credentials of its own: sso-oidc and sso:GetRoleCredentials
    # are authenticated by the bearer token, not by SigV4.
    return guard.protect(boto3.Session(), portal=portal, audit=audit)


def _write_private(path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def _read(path) -> Optional[dict]:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, ValueError):
        return None


@dataclass
class DeviceLogin:
    """A sign-in in progress: show `verification_url` to the user, then `poll()`."""

    portal_id: str
    verification_url: str
    user_code: str
    device_code: str
    interval: int
    expires_at: float


class Portal:
    """One SSO start URL and the token that unlocks every account behind it."""

    def __init__(self, portal_id: str, start_url: str, sso_region: str,
                 audit: Optional[guard.AuditLog] = None):
        self.id = portal_id
        self.start_url = start_url
        self.region = sso_region
        self.audit = audit
        self._lock = threading.Lock()
        self._session = _plain_session(audit, portal_id)

    # ----------------------------------------------------------------- files

    @property
    def _token_path(self):
        return paths.sso_dir() / f"{self.id}.json"

    @property
    def _client_path(self):
        # Client registrations are per SSO region, not per portal, and last ~90 days.
        return paths.sso_dir() / f"client-{self.region}.json"

    def _oidc(self):
        return self._session.client("sso-oidc", region_name=self.region, config=_BOTO)

    def _sso(self):
        return self._session.client("sso", region_name=self.region, config=_BOTO)

    # --------------------------------------------------------------- sign-in

    def _client_registration(self) -> dict:
        reg = _read(self._client_path)
        if reg and reg.get("clientSecretExpiresAt", 0) - _SKEW > time.time():
            return reg
        resp = self._oidc().register_client(clientName=CLIENT_NAME, clientType="public",
                                            scopes=SCOPES)
        reg = {k: resp[k] for k in ("clientId", "clientSecret", "clientSecretExpiresAt")}
        _write_private(self._client_path, reg)
        return reg

    def start_login(self) -> DeviceLogin:
        reg = self._client_registration()
        resp = self._oidc().start_device_authorization(
            clientId=reg["clientId"], clientSecret=reg["clientSecret"], startUrl=self.start_url)
        return DeviceLogin(
            portal_id=self.id,
            verification_url=resp["verificationUriComplete"],
            user_code=resp["userCode"],
            device_code=resp["deviceCode"],
            interval=int(resp.get("interval") or 5),
            expires_at=time.time() + int(resp["expiresIn"]),
        )

    def poll(self, login: DeviceLogin) -> bool:
        """One poll of the token endpoint. True once the user has approved."""
        if time.time() > login.expires_at:
            raise LoginRequired("sign-in code expired - start again")
        reg = self._client_registration()
        oidc = self._oidc()
        try:
            resp = oidc.create_token(clientId=reg["clientId"], clientSecret=reg["clientSecret"],
                                     grantType=DEVICE_GRANT, deviceCode=login.device_code)
        except oidc.exceptions.AuthorizationPendingException:
            return False
        except oidc.exceptions.SlowDownException:
            login.interval += 5
            return False
        except oidc.exceptions.AccessDeniedException as exc:
            raise LoginRequired("sign-in was denied") from exc
        except oidc.exceptions.ExpiredTokenException as exc:
            raise LoginRequired("sign-in code expired - start again") from exc
        self._save_token(resp)
        return True

    def wait_for_login(self, login: DeviceLogin) -> None:
        """Block until approved (CLI use). The web UI polls instead."""
        while not self.poll(login):
            time.sleep(login.interval)

    def _save_token(self, resp: dict) -> None:
        token = {
            "accessToken": resp["accessToken"],
            "expiresAt": time.time() + int(resp["expiresIn"]),
        }
        if resp.get("refreshToken"):
            token["refreshToken"] = resp["refreshToken"]
        _write_private(self._token_path, token)

    def logout(self) -> None:
        self._token_path.unlink(missing_ok=True)

    # ----------------------------------------------------------------- token

    def token_expires_at(self) -> Optional[float]:
        tok = _read(self._token_path)
        return tok["expiresAt"] if tok else None

    def logged_in(self) -> bool:
        try:
            self.access_token()
            return True
        except LoginRequired:
            return False

    def access_token(self) -> str:
        with self._lock:
            tok = _read(self._token_path)
            if not tok:
                raise LoginRequired(f"portal {self.id}: not signed in")
            if tok["expiresAt"] - _SKEW > time.time():
                return tok["accessToken"]
            if tok.get("refreshToken"):
                try:
                    reg = self._client_registration()
                    resp = self._oidc().create_token(
                        clientId=reg["clientId"], clientSecret=reg["clientSecret"],
                        grantType="refresh_token", refreshToken=tok["refreshToken"])
                    self._save_token(resp)
                    return resp["accessToken"]
                except Exception as exc:  # noqa: BLE001
                    log.info("portal %s: token refresh failed (%s)", self.id, exc)
            raise LoginRequired(f"portal {self.id}: session expired - sign in again")

    # ------------------------------------------------------------- discovery

    def discover(self) -> list[dict]:
        """Every account behind the portal, with the roles the user may assume in each."""
        token = self.access_token()
        sso = self._sso()
        accounts = []
        for page in sso.get_paginator("list_accounts").paginate(accessToken=token):
            for acct in page["accountList"]:
                roles = []
                for rpage in sso.get_paginator("list_account_roles").paginate(
                        accessToken=token, accountId=acct["accountId"]):
                    roles += [r["roleName"] for r in rpage["roleList"]]
                accounts.append({
                    "account_id": acct["accountId"],
                    "name": acct.get("accountName") or acct["accountId"],
                    "email": acct.get("emailAddress", ""),
                    "roles": sorted(roles),
                })
        return accounts

    def role_credentials(self, account_id: str, role_name: str) -> tuple[dict, datetime]:
        try:
            creds = self._sso().get_role_credentials(
                accessToken=self.access_token(), accountId=account_id, roleName=role_name,
            )["roleCredentials"]
        except self._sso().exceptions.UnauthorizedException as exc:
            raise LoginRequired(f"portal {self.id}: session expired - sign in again") from exc
        expires = datetime.fromtimestamp(creds["expiration"] / 1000, tz=timezone.utc)
        return creds, expires


class SSOSource:
    """Credential source for AccountSession: role credentials fetched through a portal."""

    def __init__(self, portal: Portal, account_id: str, role_name: str):
        self.portal = portal
        self.portal_id = portal.id
        self.account_id = account_id
        self.role_name = role_name

    def session(self) -> tuple[boto3.Session, datetime]:
        creds, expires = self.portal.role_credentials(self.account_id, self.role_name)
        return boto3.Session(
            aws_access_key_id=creds["accessKeyId"],
            aws_secret_access_key=creds["secretAccessKey"],
            aws_session_token=creds["sessionToken"],
        ), expires
