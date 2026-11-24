"""Create the local teaching lab. Run once; never ship generated secrets."""
import json
import secrets
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from security import RUNTIME, SENDER, b64, now, password_hash


def name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_certificate(subject, issuer, public_key, signing_key, is_ca):
    builder = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
    builder = builder.public_key(public_key).serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(now() - timedelta(minutes=5)).not_valid_after(now() + timedelta(days=365))
    builder = builder.add_extension(x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), critical=True)
    usage = x509.KeyUsage(digital_signature=not is_ca, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=is_ca,
                          crl_sign=is_ca, encipher_only=False, decipher_only=False)
    builder = builder.add_extension(usage, critical=True)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), critical=False)
    return builder.sign(signing_key, hashes.SHA256())


def initialize():
    if RUNTIME.exists():
        print("Local lab already initialized; existing data and keys retained.")
        return
    with TemporaryDirectory(dir=RUNTIME.parent) as temp:
        root = Path(temp) / "runtime"
        sender, receiver = root / "sender", root / "receiver"
        sender.mkdir(parents=True)
        receiver.mkdir()
        (receiver / "records").mkdir()
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sender_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name, sender_name = name("SecureInspect Lab CA"), name(SENDER)
        ca = make_certificate(ca_name, ca_name, ca_key.public_key(), ca_key, True)
        leaf = make_certificate(sender_name, ca_name, sender_key.public_key(), ca_key, False)
        untrusted = make_certificate(sender_name, sender_name, sender_key.public_key(), sender_key, False)
        (receiver / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (sender / "certificate.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        (sender / "untrusted.pem").write_bytes(untrusted.public_bytes(serialization.Encoding.PEM))
        (sender / "private.pem").write_bytes(sender_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (receiver / "jwt.key").write_bytes(secrets.token_bytes(32))
        (receiver / "aes.key").write_bytes(secrets.token_bytes(32))
        password = secrets.token_urlsafe(12)
        salt = secrets.token_bytes(16)
        (sender / "demo_password.txt").write_text(password, encoding="utf-8")
        (receiver / "account.json").write_text(json.dumps({"salt": b64(salt), "hash": b64(password_hash(password, salt))}), encoding="utf-8")
        root.rename(RUNTIME)
    print("Local CA, sensor certificate, RSA keys and server secrets created.")


if __name__ == "__main__":
    initialize()
    print("Demo username:", SENDER)
    print("Demo password:", (RUNTIME / "sender" / "demo_password.txt").read_text(encoding="utf-8"))
