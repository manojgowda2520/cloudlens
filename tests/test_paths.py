import stat

from cloudlens import paths


def test_state_lives_under_cloudlens_home(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDLENS_HOME", str(tmp_path / "state"))
    assert paths.database() == tmp_path / "state" / "cloudlens.db"
    assert paths.sso_dir() == tmp_path / "state" / "sso"


def test_ensure_creates_owner_only_dirs(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDLENS_HOME", str(tmp_path / "state"))
    root = paths.ensure()
    for d in (root, paths.sso_dir()):
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert paths.pricing_cache().is_dir()


def test_ensure_tightens_an_existing_loose_dir(tmp_path, monkeypatch):
    root = tmp_path / "state"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    monkeypatch.setenv("CLOUDLENS_HOME", str(root))
    paths.ensure()
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
