"""Where cloudlens keeps its state.

Everything that can identify a real AWS estate - the scan database, SSO tokens, the
account list - lives under one directory outside the repo, ~/.cloudlens by default
(override with CLOUDLENS_HOME). It is created owner-only (0700) so tokens and findings
are not readable by other local users, and so nothing in it can be committed by accident.

    ~/.cloudlens/
      config.yaml        portals, accounts, scan settings
      cloudlens.db       SQLite: inventory, findings, cost, scan history, audit log
      sso/               SSO token cache, one file per portal (0600)
      cache/pricing/     AWS Pricing API cache
"""
from __future__ import annotations

import os
from pathlib import Path

_DIR_MODE = 0o700


def home() -> Path:
    return Path(os.environ.get("CLOUDLENS_HOME") or Path.home() / ".cloudlens").expanduser()


def config_file() -> Path:
    return home() / "config.yaml"


def database() -> Path:
    return home() / "cloudlens.db"


def sso_dir() -> Path:
    return home() / "sso"


def pricing_cache() -> Path:
    return home() / "cache" / "pricing"


def ensure() -> Path:
    """Create the state directory tree owner-only, and tighten it if it already exists."""
    root = home()
    for d in (root, sso_dir(), pricing_cache()):
        d.mkdir(parents=True, exist_ok=True)
    # mkdir's mode is masked by umask and ignored for existing dirs, so chmod explicitly.
    # Only the root and sso/ hold anything sensitive; the pricing cache is public data.
    for d in (root, sso_dir()):
        os.chmod(d, _DIR_MODE)
    return root
