# NeuroGuard SDK

Privacy infrastructure for neural and biometric data. NeuroGuard protects sensitive data **before it leaves the device** via encryption, consent management, and audit logging.

## Architecture

```
neuroguard/
├── __init__.py          # Package exports: NeuralDataCipher, ConsentManager, AuditLogger
├── encryption/           # On-device encryption
│   ├── __init__.py
│   └── engine.py        # NeuralDataCipher (Fernet + optional PBKDF2 key derivation)
├── consent/             # Permission / consent manager
│   ├── __init__.py
│   └── manager.py       # ConsentManager, ConsentScope, ConsentLevel
└── audit/               # Audit logging
    ├── __init__.py
    └── logger.py       # AuditLogger, AuditEvent, AuditAction

examples/
└── encrypted_neural_processing.py   # Example: encrypt → consent check → process → audit

tests/
├── test_encryption.py
├── test_consent.py
└── test_audit.py
```

### Components

| Component | Purpose |
|-----------|--------|
| **Encryption** | Symmetric encryption (Fernet: AES-128-CBC + HMAC) for neural/biometric payloads. Keys can be generated or derived from a user secret (PBKDF2) so nothing leaves the device in plaintext. |
| **Consent manager** | Tracks and enforces user consent by scope (e.g. processing, export, analytics). Use `require_consent(scope)` before any operation that touches sensitive data. |
| **Audit logger** | Writes structured, tamper-evident log entries (action, actor, resource, outcome) for compliance and debugging. |

### Data flow (example)

1. **Encrypt** sensitive payload with `NeuralDataCipher` (key or secret).
2. **Check consent** with `ConsentManager.require_consent(ConsentScope.PROCESSING)` (or relevant scope).
3. **Log** each sensitive action with `AuditLogger.log(AuditAction.ENCRYPT, ...)`.
4. Process only when consent is granted; keep data encrypted when at rest or in transit.

## Install

```bash
pip install -e ".[dev]"
```

Or from repo root:

```bash
pip install -e .
# optional: pip install pytest pytest-cov
```

## Usage

```python
from neuroguard import NeuralDataCipher, ConsentManager, AuditLogger
from neuroguard.consent import ConsentScope
from neuroguard.audit import AuditAction

# Encrypt
cipher = NeuralDataCipher(secret="user-passphrase")
encrypted = cipher.encrypt(b"neural or biometric payload")

# Consent
consent = ConsentManager()
consent.grant(ConsentScope.PROCESSING)
consent.require_consent(ConsentScope.PROCESSING)  # raises if not granted

# Audit
audit = AuditLogger()
audit.log(AuditAction.ENCRYPT, actor="app", resource="payload", outcome="success")
```

Run the example:

```bash
python examples/encrypted_neural_processing.py
```

## Tests

```bash
pytest tests/ -v
```

## License

MIT
