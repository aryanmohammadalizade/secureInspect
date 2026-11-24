"""Cryptographic primitives used by the receiver and the local sender."""
import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import time

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

RUNTIME = Path(__file__).resolve().parent / "runtime"
SENDER = "sensor-01"
ISSUER = "secureinspect-local"
AUDIENCE = "inspection-api"


def now():
    return datetime.now(timezone.utc)


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(text):
    return base64.b64decode(text, validate=True)


def message_bytes(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


def password_valid(password, salt, expected):
    return hmac.compare_digest(password_hash(password, salt), expected)


def issue_token(username, key):
    claims = {"sub": username, "iss": ISSUER, "aud": AUDIENCE,
              "iat": now(), "exp": now() + timedelta(minutes=30)}
    return jwt.encode(claims, key, algorithm="HS256")


def verify_token(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], issuer=ISSUER, audience=AUDIENCE,
                      options={"require": ["sub", "iss", "aud", "iat", "exp"]})


def sign(data, private_key):
    return b64(private_key.sign(message_bytes(data), padding.PKCS1v15(), hashes.SHA256()))


def verify_signature(data, signature, public_key):
    public_key.verify(unb64(signature), message_bytes(data), padding.PKCS1v15(), hashes.SHA256())


def certificate_key(pem, trusted_ca, identity):
    cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
    for item in (trusted_ca, cert):
        if not item.not_valid_before_utc <= now() <= item.not_valid_after_utc:
            raise ValueError("Certificate has expired or is not yet valid.")
    cert.verify_directly_issued_by(trusted_ca)
    if not trusted_ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Invalid trust anchor.")
    if not trusted_ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
        raise ValueError("CA is not permitted to sign certificates.")
    if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Expected a sender certificate, not a CA certificate.")
    if not cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature:
        raise ValueError("Certificate is not permitted to sign messages.")
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(names) != 1 or names[0].value != identity:
        raise ValueError("Certificate identity does not match the authenticated sender.")
    key = cert.public_key()
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise ValueError("Expected an RSA key of at least 2048 bits.")
    return key


def encrypt(data, key, record_id):
    nonce = secrets.token_bytes(12)
    aad = record_id.encode()
    ciphertext = AESGCM(key).encrypt(nonce, message_bytes(data), aad)
    return {"nonce": b64(nonce), "ciphertext": b64(ciphertext)}


def decrypt(record, key, record_id):
    plaintext = AESGCM(key).decrypt(unb64(record["nonce"]), unb64(record["ciphertext"]), record_id.encode())
    return json.loads(plaintext)


def fresh(signed_at):
    return -30 <= time() - signed_at <= 300
