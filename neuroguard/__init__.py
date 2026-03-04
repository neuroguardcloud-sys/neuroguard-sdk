"""
NeuroGuard — Privacy infrastructure for neural and biometric data.

Protects sensitive data before it leaves the device via:
- Encryption: on-device encryption with key derivation
- Consent: permission and consent management
- Audit: tamper-evident audit logging
"""

from neuroguard.encryption import NeuralDataCipher
from neuroguard.consent import ConsentManager
from neuroguard.audit import AuditLogger
from neuroguard.vault import NeuralDataVault

__version__ = "0.1.0"
__all__ = ["NeuralDataCipher", "ConsentManager", "AuditLogger", "NeuralDataVault"]
