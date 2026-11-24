"""Local sender simulator: signs only predefined synthetic inspection examples."""
from uuid import uuid4
from time import time

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from security import RUNTIME, SENDER, sign


def prepare_reading(scenario="genuine"):
    reading = {"message_id": str(uuid4()), "sender": SENDER, "asset": "CAISSON-01",
               "previous_year": 2023, "current_year": 2026, "previous_mm": 10.0, "current_mm": 7.0,
               "signed_at": int(time())}
    if scenario == "faulty":
        reading["current_mm"] = 12.5
    if scenario == "stale":
        reading["signed_at"] -= 600
    folder = RUNTIME / "sender"
    private_key = load_pem_private_key((folder / "private.pem").read_bytes(), password=None)
    signature = sign(reading, private_key)
    return {"reading": reading, "signature": signature,
            "certificate": (folder / "certificate.pem").read_text(encoding="ascii")}


def untrusted_certificate():
    return (RUNTIME / "sender" / "untrusted.pem").read_text(encoding="ascii")
