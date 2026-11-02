import pytest
from fastapi.testclient import TestClient

from cloudlens.demo import build
from cloudlens.web.app import create_app
from cloudlens.workspace import Workspace


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDLENS_HOME", str(tmp_path))
    db = tmp_path / "demo.db"
    build(db)
    ws = Workspace(db_path=db)
    app = create_app(ws, demo=True, allowed_hosts={"testserver"})
    with TestClient(app) as c:
        yield c
    ws.close()


def _csrf(client):
    html = client.get("/").text
    return html.split('name="csrf" content="')[1].split('"')[0]


@pytest.mark.parametrize("path", ["/", "/findings", "/findings?severity=Critical", "/findings?view=new",
                                  "/findings?view=suppressed", "/inventory", "/inventory?service=lambda&q=trip",
                                  "/cost", "/scans", "/scans/2", "/diff?a=1&b=2", "/portals", "/audit",
                                  "/report/111111111111", "/export/findings.csv", "/export/inventory.csv"])
def test_pages_render(client, path):
    r = client.get(path)
    assert r.status_code == 200, r.text[:500]


def test_demo_has_findings_from_real_checks(client):
    html = client.get("/findings").text
    for check in ("IAM-06", "LMB-04", "S3-01", "NET-01", "DNS-03", "DNS-04", "IAM-08", "DAT-02"):
        assert check in html, check


def test_resource_page(client):
    r = client.get("/resource", params={"arn": "arn:aws:s3:::mobility-dev-trip-logs"})
    assert r.status_code == 200


def test_post_needs_csrf_token(client):
    assert client.post("/suppress", data={"check_id": "X", "arn": "y", "reason": "z"}).status_code == 403
    r = client.post("/suppress", data={"check_id": "X", "arn": "y", "reason": "z"},
                    headers={"X-CSRF-Token": _csrf(client)})
    assert r.status_code == 204


def test_foreign_host_rejected(client):
    assert client.get("/", headers={"host": "evil.example"}).status_code == 403


def test_scan_disabled_in_demo(client):
    r = client.post("/scan", headers={"X-CSRF-Token": _csrf(client)})
    assert r.status_code == 400
