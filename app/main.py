"""Passerelle OAuth2 TrackDéchets — garde le client_secret et le jeton côté serveur.

Le frontend (PWA statique) n'a jamais ni le secret ni le jeton : il obtient une
session HttpOnly, et les appels à TrackDéchets passent par /api/trackdechets/*.

Routes
  GET  /health
  GET  /oauth2/trackdechets/start        -> redirige vers le dialogue d'autorisation
  GET  /oauth2/trackdechets/callback     -> échange le code, crée la session
  GET  /api/session                      -> {authenticated, email}
  POST /api/trackdechets/draft-bsff      -> crée un brouillon BSFF (jeton serveur)
  POST /oauth2/trackdechets/logout       -> supprime la session

Variables d'environnement
  TDC_CLIENT_ID, TDC_CLIENT_SECRET (obligatoires)
  TDC_ENV = sandbox | production (défaut sandbox)
  APP_ORIGIN = origine autorisée en CORS (défaut https://thebestsystem.github.io)
  DB_PATH (défaut /data/frigo_oauth.db)
"""
from __future__ import annotations

import base64
import os
import secrets
import sqlite3
import time
from contextlib import closing
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

ENV = os.environ.get("TDC_ENV", "sandbox").lower()
CLIENT_ID = os.environ.get("TDC_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("TDC_CLIENT_SECRET", "")
APP_ORIGIN = os.environ.get("APP_ORIGIN", "https://thebestsystem.github.io")
DB_PATH = os.environ.get("DB_PATH", "/data/frigo_oauth.db")
STATE_TTL = 600  # 10 minutes, comme le code d'autorisation

ENDPOINTS = {
    "sandbox": {
        "authorize": "https://sandbox.trackdechets.beta.gouv.fr/oauth2/authorize/dialog",
        "token": "https://api.sandbox.trackdechets.beta.gouv.fr/oauth2/token",
        "graphql": "https://api.sandbox.trackdechets.beta.gouv.fr",
    },
    "production": {
        "authorize": "https://app.trackdechets.beta.gouv.fr/oauth2/authorize/dialog",
        "token": "https://api.trackdechets.beta.gouv.fr/oauth2/token",
        "graphql": "https://api.trackdechets.beta.gouv.fr",
    },
}

CREATE_DRAFT_BSFF = """
mutation CreateDraftBsff($input: BsffInput!) {
  createDraftBsff(input: $input) { id }
}
"""

app = FastAPI(title="Frigo — passerelle TrackDéchets", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[APP_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


# ---------------------------------------------------------------- persistance
def db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS states (state TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (
            sid TEXT PRIMARY KEY, token TEXT NOT NULL, email TEXT, created_at INTEGER NOT NULL
        );
        """
    )
    return conn


def put_state(state: str) -> None:
    with closing(db()) as conn:
        conn.execute("DELETE FROM states WHERE created_at < ?", (int(time.time()) - STATE_TTL,))
        conn.execute("INSERT OR REPLACE INTO states VALUES (?, ?)", (state, int(time.time())))
        conn.commit()


def pop_state(state: str) -> bool:
    with closing(db()) as conn:
        row = conn.execute("SELECT created_at FROM states WHERE state = ?", (state,)).fetchone()
        if not row:
            return False
        conn.execute("DELETE FROM states WHERE state = ?", (state,))
        conn.commit()
        return int(time.time()) - int(row["created_at"]) <= STATE_TTL


def create_session(token: str, email: str | None) -> str:
    sid = secrets.token_urlsafe(32)
    with closing(db()) as conn:
        conn.execute("INSERT INTO sessions VALUES (?,?,?,?)", (sid, token, email, int(time.time())))
        conn.commit()
    return sid


def get_session(sid: str | None) -> sqlite3.Row | None:
    if not sid:
        return None
    with closing(db()) as conn:
        return conn.execute("SELECT * FROM sessions WHERE sid = ?", (sid,)).fetchone()


# ------------------------------------------------------------------ fonctions
def redirect_uri(request: Request) -> str:
    """L'URL de retour doit être identique à celle déclarée dans l'application."""
    return str(request.url_for("callback"))


async def exchange_code(code: str, uri: str) -> dict:
    """Échange code -> jeton. Basic auth avec client_id/client_secret."""
    basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(
            ENDPOINTS[ENV]["token"],
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": uri},
            headers={"Authorization": f"Basic {basic}",
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"échange refusé ({r.status_code}): {r.text[:200]}")
    return r.json()


class DraftRequest(BaseModel):
    input: dict


# --------------------------------------------------------------------- routes
@app.get("/health")
def health() -> dict:
    return {"status": "ok", "env": ENV, "client_id_set": bool(CLIENT_ID),
            "secret_set": bool(CLIENT_SECRET)}


@app.get("/oauth2/trackdechets/start")
def start(request: Request) -> RedirectResponse:
    if not CLIENT_ID or not CLIENT_SECRET:
        raise HTTPException(500, "TDC_CLIENT_ID / TDC_CLIENT_SECRET non configurés")
    state = secrets.token_urlsafe(24)
    put_state(state)
    params = urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri(request),
        "state": state,
    })
    return RedirectResponse(f"{ENDPOINTS[ENV]['authorize']}?{params}", status_code=302)


@app.get("/oauth2/trackdechets/callback", name="callback")
async def callback(request: Request, code: str | None = None, state: str | None = None,
                   error: str | None = None) -> Response:
    if error:
        return RedirectResponse(f"{APP_ORIGIN}/frigo-app/?trackdechets=error&reason={error}", status_code=302)
    if not code or not state or not pop_state(state):
        return RedirectResponse(f"{APP_ORIGIN}/frigo-app/?trackdechets=error&reason=state", status_code=302)

    data = await exchange_code(code, redirect_uri(request))
    token = data.get("access_token")
    if not token:
        return RedirectResponse(f"{APP_ORIGIN}/frigo-app/?trackdechets=error&reason=token", status_code=302)

    email = (data.get("user") or {}).get("email")
    sid = create_session(token, email)
    response = RedirectResponse(f"{APP_ORIGIN}/frigo-app/?trackdechets=ok", status_code=302)
    response.set_cookie("frigo_sid", sid, httponly=True, secure=True, samesite="none",
                        max_age=60 * 60 * 24 * 365)
    return response


@app.get("/api/session")
def session(request: Request) -> dict:
    row = get_session(request.cookies.get("frigo_sid"))
    return {"authenticated": bool(row), "email": row["email"] if row else None, "env": ENV}


@app.post("/api/trackdechets/draft-bsff")
async def draft_bsff(payload: DraftRequest, request: Request) -> JSONResponse:
    row = get_session(request.cookies.get("frigo_sid"))
    if not row:
        raise HTTPException(401, "session absente : autorise l'application TrackDéchets d'abord")
    body = {"query": CREATE_DRAFT_BSFF, "variables": {"input": payload.input}}
    async with httpx.AsyncClient(timeout=25) as client:
        r = await client.post(ENDPOINTS[ENV]["graphql"], json=body,
                              headers={"Authorization": f"Bearer {row['token']}"})
    try:
        data = r.json()
    except Exception:
        return JSONResponse({"ok": False, "error": f"réponse illisible ({r.status_code})"}, status_code=502)
    if data.get("errors"):
        return JSONResponse({"ok": False, "error": data["errors"][0].get("message", "erreur GraphQL")},
                            status_code=200)
    bsff = (data.get("data") or {}).get("createDraftBsff") or {}
    return JSONResponse({"ok": True, "id": bsff.get("id")})


@app.post("/oauth2/trackdechets/logout")
def logout(request: Request) -> Response:
    sid = request.cookies.get("frigo_sid")
    if sid:
        with closing(db()) as conn:
            conn.execute("DELETE FROM sessions WHERE sid = ?", (sid,))
            conn.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie("frigo_sid")
    return response
