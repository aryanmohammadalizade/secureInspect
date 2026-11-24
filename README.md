# SecureInspect

SEC-PRJ-7E_25 — Fake Data Prevention with Conventional Cryptotools

System Security, University of Messina. Independent academic prototype for protecting synthetic ultrasonic inspection data before corrosion forecasting. No company data, source code or infrastructure is used.

## Run

Python 3.11 or newer. Open this directory in PyCharm. On Windows, run `START_WINDOWS.bat` or use PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

On Linux/macOS, use `python3 -m venv .venv`, `.venv/bin/python -m pip install -r requirements.txt`, and `.venv/bin/python main.py`.

Open http://127.0.0.1:8000/ and sign in as `sensor-01` using the password printed in the terminal. The first launch generates local keys, certificates and credentials; subsequent launches retain them. Stop with Ctrl+C. API documentation: http://127.0.0.1:8000/docs.

## Demonstration

1. Prepare a genuine reading and select Verify & store (HTTP 201). Decrypt the accepted record to recover the original JSON.
2. Prepare a new reading, modify the received thickness to 10 mm, and verify (HTTP 400, signature). The hypothetical forecast is 10 mm rather than 4 mm; no verified forecast or record is produced.
3. Prepare a faulty signed reading (12.5 mm) and verify (HTTP 400, plausibility). Its cryptographic checks pass.
4. Prepare a stale reading (HTTP 400, freshness), or submit an accepted envelope again within five minutes (HTTP 409, replay).
5. Try the untrusted certificate, corrupted signature, invalid JWT or missing JWT options. Review the audit log and measured verification time.

## Source files

- `main.py`: API, authentication, verification and storage.
- `security.py`: JWT, password hashing, X.509, RSA signatures and AES-GCM.
- `setup_lab.py`: local CA, sender certificate and key generation.
- `client.py`: synthetic sender simulator.
- `prediction.py`: linear forecast and illustrative engineering checks.
- `web/`: browser interface.

## Scope and limitations

This is a single-user localhost demonstration, not a deployed security service. The sender is simulated on the same machine; the CA is locally trusted and has no revocation service. Private keys are not password-encrypted on disk; protect the runtime directory. Never commit or distribute `runtime/`, generated secrets or `.venv/`. HTTP is local only; production use requires TLS, separate trust boundaries, secure key storage, access controls and hardened persistence. The preview endpoint is a non-persisting counterfactual calculator, not an approval path. The corrosion model is linear extrapolation, not trained AI. All measurements and thresholds are fictional, not engineering acceptance criteria. Signatures establish origin and integrity, not physical truth. The project and documentation were developed with AI assistance.
