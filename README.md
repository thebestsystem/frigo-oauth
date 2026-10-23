# Frigo — passerelle OAuth2 TrackDéchets

Petit service FastAPI qui garde le `client_secret` et le jeton TrackDéchets **côté serveur**.
Le frontend statique (PWA) ne détient jamais le secret : il obtient une session HttpOnly.

## Routes
| Route | Rôle |
|---|---|
| `GET /health` | état + configuration présente (jamais le secret) |
| `GET /oauth2/trackdechets/start` | génère un `state`, redirige vers le dialogue d'autorisation |
| `GET /oauth2/trackdechets/callback` | échange le code (Basic auth), crée la session, redirige vers l'app |
| `GET /api/session` | `{authenticated, email, env}` |
| `POST /api/trackdechets/draft-bsff` | crée un brouillon BSFF avec le jeton serveur |
| `POST /oauth2/trackdechets/logout` | supprime la session |

## Déploiement Railway (à faire une fois)
1. New Project → **Deploy from GitHub repo** → `thebestsystem/frigo-oauth`.
2. Dans le service : **Settings → Networking → Public Networking**, choisir le domaine
   `trackdechets` → l'URL devient `https://trackdechets.up.railway.app`.
3. **Variables** :
   - `TDC_CLIENT_ID` = celui de l'application TrackDéchets
   - `TDC_CLIENT_SECRET` = le secret (jamais dans le repo)
   - `TDC_ENV` = `sandbox` (puis `production`)
   - `APP_ORIGIN` = `https://thebestsystem.github.io`
4. **Volume** monté sur `/data` (persistance des sessions) — sinon les sessions sautent à chaque déploiement.
5. Vérifier `GET https://trackdechets.up.railway.app/health` → `client_id_set: true`, `secret_set: true`.

## Vérification locale
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q          # 8 tests, aucun appel réseau
.venv/bin/uvicorn app.main:app --port 8081
curl localhost:8081/health
```

## Sécurité
- `client_secret` uniquement en variable d'environnement serveur.
- `state` à usage unique, TTL 600 s (le code TrackDéchets expire à 10 min).
- Cookie de session `HttpOnly`, `Secure`, `SameSite=None` (app et API sur deux domaines).
- Le jeton OAuth TrackDéchets a une durée de vie infinie : il est stocké en base, jamais renvoyé au navigateur.
