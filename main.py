"""SEC-PRJ-7E_25 — Fake Data Prevention with Conventional Cryptotools."""
import json
from pathlib import Path
from time import perf_counter
from typing import Literal
from uuid import UUID

import jwt
import uvicorn
from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

import client
from prediction import forecast, plausibility
from security import (RUNTIME, SENDER, certificate_key, decrypt, encrypt, issue_token,
                      password_valid, unb64, verify_signature, verify_token, fresh, now)
from setup_lab import initialize

WEB = Path(__file__).resolve().parent / "web"
SERVER = RUNTIME / "receiver"
app = FastAPI(title="SecureInspect | SEC-PRJ-7E_25", version="2.0")
app.mount("/web", StaticFiles(directory=WEB), name="web")
bearer = HTTPBearer(auto_error=False)


class Login(BaseModel):
    username: str = Field(max_length=80)
    password: str = Field(max_length=128)


class Reading(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message_id: UUID
    signed_at: int = Field(strict=True, ge=0, le=253402300799)
    sender: Literal["sensor-01"]
    asset: Literal["CAISSON-01"]
    previous_year: Literal[2023]
    current_year: Literal[2026]
    previous_mm: float = Field(gt=0, le=100, allow_inf_nan=False)
    current_mm: float = Field(gt=0, le=100, allow_inf_nan=False)


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reading: Reading
    signature: str = Field(max_length=1024)
    certificate: str = Field(max_length=12000)


@app.middleware("http")
async def audit_verification(request: Request, call_next):
    if request.url.path != "/api/verify" or request.method != "POST":
        return await call_next(request)
    start = perf_counter()
    response = await call_next(request)
    elapsed = round((perf_counter() - start) * 1000, 3)
    stage = getattr(request.state, "stage", {401: "jwt", 422: "schema"}.get(response.status_code, "other"))
    event = {"time": now().isoformat(), "stage": stage, "status": response.status_code, "latency_ms": elapsed}
    with (SERVER / "audit.jsonl").open("a", encoding="utf-8") as log:
        log.write(json.dumps(event) + "\n")
    response.headers["X-Verification-Ms"] = str(elapsed)
    return response


def authenticate(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    try:
        if credentials is None:
            raise ValueError("Missing bearer token")
        claims = verify_token(credentials.credentials, (SERVER / "jwt.key").read_bytes())
        if claims["sub"] != SENDER:
            raise ValueError("Unknown sender")
        return claims["sub"]
    except (jwt.InvalidTokenError, ValueError):
        raise HTTPException(401, "Missing, invalid or expired JWT.", headers={"WWW-Authenticate": "Bearer"})


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(WEB / "index.html")


@app.post("/api/login")
def login(body: Login):
    account = json.loads((SERVER / "account.json").read_text(encoding="utf-8"))
    if body.username != SENDER or not password_valid(body.password, unb64(account["salt"]), unb64(account["hash"])):
        raise HTTPException(401, "Incorrect username or password.")
    return {"access_token": issue_token(body.username, (SERVER / "jwt.key").read_bytes()), "token_type": "bearer"}


@app.post("/api/prepare")
def prepare(scenario: Literal["genuine", "faulty", "stale"] = "genuine", user: str = Depends(authenticate)):
    return {"envelope": client.prepare_reading(scenario), "untrusted_certificate": client.untrusted_certificate()}


@app.post("/api/preview")
def preview(reading: Reading):
    return forecast(reading.model_dump(mode="json"))


@app.post("/api/verify", status_code=201)
def verify(body: Envelope, request: Request, user: str = Depends(authenticate)):
    data = body.reading.model_dump(mode="json")
    ca = x509.load_pem_x509_certificate((SERVER / "ca.pem").read_bytes())
    request.state.stage = "certificate"
    try:
        if data["sender"] != user:
            raise ValueError("Sender identity mismatch")
        key = certificate_key(body.certificate, ca, user)
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm, x509.ExtensionNotFound):
        return JSONResponse(status_code=400, content={"detail": "Certificate or sender identity rejected.", "stage": "certificate"})
    request.state.stage = "signature"
    try:
        verify_signature(data, body.signature, key)
    except (ValueError, InvalidSignature):
        return JSONResponse(status_code=400, content={"detail": "Digital signature invalid; data may have been altered.", "stage": "signature"})
    request.state.stage = "freshness"
    if not fresh(data["signed_at"]):
        return JSONResponse(status_code=400, content={"detail": "Signed timestamp is too old or too far in the future.", "stage": "freshness"})
    request.state.stage = "plausibility"
    warning = plausibility(data)
    if warning:
        return JSONResponse(status_code=400, content={"detail": warning, "stage": "plausibility"})
    request.state.stage = "replay"
    record_id = data["message_id"]
    encrypted = encrypt(data, (SERVER / "aes.key").read_bytes(), record_id)
    try:
        with (SERVER / "records" / f"{record_id}.json").open("x", encoding="utf-8") as file:
            json.dump(encrypted, file)
    except FileExistsError:
        return JSONResponse(status_code=409, content={"detail": "This signed message was already accepted.", "stage": "replay"})
    request.state.stage = "accepted"
    return {"record_id": record_id, "encrypted": encrypted, "forecast": forecast(data)}


@app.get("/api/audit")
def recent_audit(user: str = Depends(authenticate)):
    path = SERVER / "audit.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()[-8:]] if path.exists() else []


@app.get("/api/records/{record_id}")
def read_record(record_id: UUID, user: str = Depends(authenticate)):
    path = SERVER / "records" / f"{record_id}.json"
    if not path.exists():
        raise HTTPException(404, "Record not found.")
    try:
        encrypted = json.loads(path.read_text(encoding="utf-8"))
        data = decrypt(encrypted, (SERVER / "aes.key").read_bytes(), str(record_id))
    except (InvalidTag, ValueError, KeyError, TypeError):
        raise HTTPException(400, "Stored record failed authentication.")
    return {"reading": data, "forecast": forecast(data)}


if __name__ == "__main__":
    initialize()
    print("Demo username:", SENDER)
    print("Demo password:", (RUNTIME / "sender" / "demo_password.txt").read_text(encoding="utf-8"))
    print("Open http://127.0.0.1:8000 in your browser.")
    uvicorn.run(app, host="127.0.0.1", port=8000)
