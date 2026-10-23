"""Tests de la passerelle OAuth2 — aucun appel réseau réel."""
import os
import sys
import pathlib

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
os.environ.update({
    "TDC_CLIENT_ID": "test_client",
    "TDC_CLIENT_SECRET": "test_secret",
    "DB_PATH": str(pathlib.Path(__file__).parent / "test.db"),
    "APP_ORIGIN": "https://app.test",
    "TDC_ENV": "sandbox",
})

from app import main  # noqa: E402


@pytest.fixture(autouse=True)
def clean_db():
    p = pathlib.Path(os.environ["DB_PATH"])
    if p.exists():
        p.unlink()
    yield
    if p.exists():
        p.unlink()


@pytest.fixture
def client():
    return TestClient(main.app, follow_redirects=False)


def test_health_reports_configuration(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["client_id_set"] is True
    assert "test_secret" not in r.text


def test_start_redirects_with_state_and_client_id(client):
    r = client.get("/oauth2/trackdechets/start")
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith(main.ENDPOINTS["sandbox"]["authorize"])
    assert "client_id=test_client" in loc and "state=" in loc
    assert "response_type=code" in loc


def test_callback_rejects_unknown_state(client):
    r = client.get("/oauth2/trackdechets/callback?code=abc&state=inconnu")
    assert r.status_code == 302
    assert "trackdechets=error" in r.headers["location"] and "reason=state" in r.headers["location"]


def test_callback_exchanges_code_and_sets_cookie(client, monkeypatch):
    async def fake_exchange(code, uri):
        assert code == "good"
        return {"access_token": "tok_123", "user": {"email": "a@b.fr"}}

    monkeypatch.setattr(main, "exchange_code", fake_exchange)
    main.put_state("s1")
    r = client.get("/oauth2/trackdechets/callback?code=good&state=s1")
    assert r.status_code == 302 and "trackdechets=ok" in r.headers["location"]
    cookie = r.headers.get("set-cookie", "")
    assert "frigo_sid=" in cookie and "HttpOnly" in cookie

    sid = cookie.split("frigo_sid=")[1].split(";")[0]
    s = client.get("/api/session", cookies={"frigo_sid": sid}).json()
    assert s["authenticated"] is True and s["email"] == "a@b.fr"


def test_callback_state_is_single_use(client, monkeypatch):
    async def fake_exchange(code, uri):
        return {"access_token": "tok", "user": {}}

    monkeypatch.setattr(main, "exchange_code", fake_exchange)
    main.put_state("s2")
    assert client.get("/oauth2/trackdechets/callback?code=c&state=s2").status_code == 302
    r = client.get("/oauth2/trackdechets/callback?code=c&state=s2")
    assert "reason=state" in r.headers["location"]


def test_draft_requires_session(client):
    r = client.post("/api/trackdechets/draft-bsff", json={"input": {"type": "BSFF"}})
    assert r.status_code == 401


def test_draft_uses_server_side_token(client, monkeypatch):
    sid = main.create_session("tok_abc", "a@b.fr")
    captured = {}

    class FakeResponse:
        status_code = 200
        def json(self):
            return {"data": {"createDraftBsff": {"id": "bsff_42"}}}

    class FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, headers=None):
            captured["url"], captured["json"], captured["auth"] = url, json, headers["Authorization"]
            return FakeResponse()

    monkeypatch.setattr(main.httpx, "AsyncClient", FakeClient)
    r = client.post("/api/trackdechets/draft-bsff", json={"input": {"type": "BSFF"}},
                    cookies={"frigo_sid": sid})
    assert r.status_code == 200 and r.json() == {"ok": True, "id": "bsff_42"}
    assert captured["auth"] == "Bearer tok_abc"
    assert captured["json"]["variables"]["input"]["type"] == "BSFF"


def test_draft_surfaces_graphql_error(client, monkeypatch):
    sid = main.create_session("tok_err", None)

    class FakeResponse:
        status_code = 200
        def json(self):
            return {"errors": [{"message": "SIRET invalide"}]}

    class FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return FakeResponse()

    monkeypatch.setattr(main.httpx, "AsyncClient", FakeClient)
    r = client.post("/api/trackdechets/draft-bsff", json={"input": {}}, cookies={"frigo_sid": sid})
    assert r.json() == {"ok": False, "error": "SIRET invalide"}


def test_redirect_uri_uses_public_base_url(monkeypatch):
    """Sur Railway le TLS est terminé en amont : http:// ne doit jamais fuiter."""
    monkeypatch.setattr(main, "PUBLIC_BASE_URL", "https://trackdechets.up.railway.app")

    class FakeRequest:
        def url_for(self, name):
            return "http://trackdechets.up.railway.app/oauth2/trackdechets/callback"

    assert main.redirect_uri(FakeRequest()) == \
        "https://trackdechets.up.railway.app/oauth2/trackdechets/callback"


def test_redirect_uri_forces_https_behind_proxy(monkeypatch):
    monkeypatch.setattr(main, "PUBLIC_BASE_URL", "")

    class FakeRequest:
        headers = {"x-forwarded-host": "trackdechets.up.railway.app"}
        class url:
            netloc = "trackdechets.up.railway.app"
            scheme = "http"
        def url_for(self, name):
            return "http://trackdechets.up.railway.app/oauth2/trackdechets/callback"

    assert main.redirect_uri(FakeRequest()) == \
        "https://trackdechets.up.railway.app/oauth2/trackdechets/callback"
