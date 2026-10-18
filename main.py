import os
from pathlib import Path

import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-9li020y9.apps.exam.local"

# Public key: env var PUBLIC_KEY wins, otherwise read public_key.pem next to this file.
PUBLIC_KEY = os.environ.get("PUBLIC_KEY") or (
    Path(__file__).parent / "public_key.pem"
).read_text()

app = FastAPI()


def invalid() -> JSONResponse:
    return JSONResponse(status_code=401, content={"valid": False})


@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        token = body.get("token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            return invalid()

        claims = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],  # never trust the token's own alg header
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iss", "aud"], "verify_exp": True},
        )

        aud = claims.get("aud")
        if isinstance(aud, list):
            aud = AUDIENCE
        return {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": aud,
        }
    except Exception:
        return invalid()
