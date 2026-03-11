# NeuroGuard

Privacy infrastructure for neural, biometric, and cognitive data.

NeuroGuard protects sensitive data **before it leaves the device** — with on-device encryption, consent enforcement, and tamper-evident audit logging built into your application at the code level.

## Install
```bash
pip install neuroguard
```

## Quickstart
```python
from neuroguard import NeuralDataCipher, ConsentManager, AuditLogger
from neuroguard.consent import ConsentScope
from neuroguard.audit import AuditAction

# Encrypt on-device before anything else touches the data
cipher = NeuralDataCipher(secret="user-passphrase")
encrypted = cipher.encrypt(b"neural or biometric payload")

# Enforce consent before processing
consent = ConsentManager()
consent.grant(ConsentScope.PROCESSING)
consent.require_consent(ConsentScope.PROCESSING)

# Tamper-evident audit log
audit = AuditLogger()
audit.log(AuditAction.ENCRYPT, actor="app", resource="payload", outcome="success")
```

## Why NeuroGuard

Traditional security protects data after it reaches servers. Neural and biometric data is too sensitive for that model.

NeuroGuard enforces privacy at the point of collection — before any network, framework, or server can see raw data.

## Architecture

| Component | Purpose |
|-----------|---------|
| `NeuralDataCipher` | On-device AES-128-CBC + HMAC encryption. Key or passphrase-derived via PBKDF2. |
| `ConsentManager` | Grant, revoke, and enforce consent by scope. Blocks operations if consent is not active. |
| `ConsentLedger` | Append-only, hash-chained log of every consent event. Tamper-evident. Exportable for auditors. |
| `AuditLogger` | Structured log entries for every sensitive action — actor, resource, outcome, timestamp. |
| Local REST API | FastAPI server: health, vault, consent, and compliance endpoints. Run locally, integrate anywhere. |

## Local API
```bash
python -m neuroguard.api
```

Server runs at `http://127.0.0.1:8000`. API docs at `http://127.0.0.1:8000/docs`.

## Consent Ledger
```python
from neuroguard.consent import ConsentManager, ConsentLedger, ConsentScope

ledger = ConsentLedger()
consent = ConsentManager(consent_ledger=ledger, ledger_user_id="user_123")
consent.grant(ConsentScope.PROCESSING)
consent.revoke(ConsentScope.PROCESSING)

assert ledger.verify_chain() is True
print(ledger.export_json(user_id="user_123"))
```

## Run Tests
```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Project Structure
```
neuroguard/
├── encryption/        # NeuralDataCipher — AES-128-CBC + HMAC
├── consent/           # ConsentManager, ConsentScope, ConsentLedger
├── audit/             # AuditLogger, AuditEvent, AuditAction
├── vault/             # Vault storage backend
├── lineage/           # Data lineage tracking
├── db/                # Schema definitions
├── api/               # FastAPI local REST API
├── api_keys.py        # API key management
├── client.py          # SDK client
├── plans.py           # Plan definitions
├── subscriptions.py   # Subscription state
├── tenants.py         # Tenant management
├── usage_meter.py     # Usage tracking
└── settings.py        # Configuration

examples/
└── encrypted_neural_processing.py

tests/
├── test_encryption.py
├── test_consent.py
├── test_consent_ledger.py
├── test_audit.py
├── test_vault.py
├── test_vault_backend.py
├── test_api.py
├── test_api_keys.py
├── test_api_pdf_report.py
├── test_api_evidence_bundle.py
├── test_client.py
├── test_plans.py
├── test_subscriptions.py
├── test_tenants.py
├── test_usage_meter.py
└── test_privacy_score.py
```

## License

NeuroGuard is released under the [Business Source License 1.1](LICENSE).

Free for non-commercial and internal business use. Commercial use requires a license.
On 2029-01-01 this software converts to MIT.
