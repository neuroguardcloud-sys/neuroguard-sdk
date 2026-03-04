"""
Example: Encrypted neural data processing with NeuroGuard.

Demonstrates:
1. Request/grant consent for a data category
2. Encrypt a sample neural signal
3. Store encrypted payload in the vault
4. Retrieve from vault and decrypt (only with consent)
5. Show that audit events are recorded for every operation
"""

import io
import json
import sys

# Add parent so we can import neuroguard when run from repo root
sys.path.insert(0, ".")

from neuroguard import NeuralDataCipher, ConsentManager, AuditLogger, NeuralDataVault
from neuroguard.consent import ConsentScope
from neuroguard.audit import AuditAction


def main() -> None:
    # 1. Request/grant consent for the category we will store/retrieve
    consent = ConsentManager()
    category = "neural_signals"
    consent.grant_category(category)
    consent.grant(ConsentScope.PROCESSING, metadata={"purpose": "local_inference"})

    # 2. Encrypt a sample neural signal
    cipher = NeuralDataCipher(secret="user-passphrase")
    raw_data = json.dumps({"signals": [0.1, -0.2, 0.3], "timestamp": 1234567890}).encode()
    encrypted = cipher.encrypt(raw_data)
    print("Encrypted payload length:", len(encrypted))

    # 3. Audit logger (capture output to show events)
    audit = AuditLogger(stream=io.StringIO())
    audit.log(
        AuditAction.ENCRYPT,
        actor="sdk_example",
        resource="neural_payload",
        outcome="success",
        size_bytes=len(encrypted),
    )

    # 4. Store encrypted payload in the vault
    vault = NeuralDataVault(consent_manager=consent, audit_logger=audit)
    user_id = "user_001"
    vault.store(user_id, category, encrypted)
    print("Stored encrypted data in vault for", user_id, "category", category)

    # 5. Retrieve from vault (consent already granted) and decrypt
    retrieved = vault.retrieve(user_id, category)
    decrypted = cipher.decrypt(retrieved)
    data = json.loads(decrypted.decode())
    print("Retrieved and decrypted:", data)

    # 6. Show audit events recorded for every operation
    events = audit.get_events()
    print("\nAudit events recorded:", len(events))
    for evt in events:
        print("  ", evt.to_json())

    # Demonstrate: revoke consent and show retrieve is denied
    consent.revoke_category(category)
    try:
        vault.retrieve(user_id, category)
    except PermissionError as e:
        print("\nAfter revoking consent, retrieve correctly raises:", e)
    events_after_denial = audit.get_events()
    print("Audit events after denied retrieve:", len(events_after_denial))


if __name__ == "__main__":
    main()
