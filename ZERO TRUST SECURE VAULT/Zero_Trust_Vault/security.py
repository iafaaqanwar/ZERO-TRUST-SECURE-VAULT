"""
==============================================================================
 security.py — Zero Trust Secure Vault :: Cryptographic Engine
==============================================================================
 This module implements the core security primitives for the Zero Trust Vault:

   1. Symmetric Encryption (Fernet / AES-128-CBC + HMAC-SHA256)
      → Provides **Data at Rest** protection.  Every file stored on disk is
        encrypted; plaintext bytes never touch the filesystem.

   2. SHA-256 Cryptographic Hashing
      → Provides **Data Integrity** verification.  A hash fingerprint is
        recorded at upload time and re-verified at every download / preview,
        enabling tamper detection (integrity validation).

   3. Master Key Management
      → A single Fernet master key is generated once and persisted in
        `storage/secret.key`.  In a production environment this key would
        reside in a Hardware Security Module (HSM) or cloud KMS.

 Security Concepts Demonstrated:
   ┌─────────────────────────┬──────────────────────────────────────────────┐
   │ Concept                 │ Implementation                               │
   ├─────────────────────────┼──────────────────────────────────────────────┤
   │ Confidentiality         │ Fernet (AES-128-CBC) encryption              │
   │ Integrity               │ SHA-256 hash comparison                      │
   │ Authentication          │ HMAC built into Fernet token                 │
   │ Non-repudiation         │ Audit logs tied to crypto operations         │
   └─────────────────────────┴──────────────────────────────────────────────┘
==============================================================================
"""

import os
import hashlib
from cryptography.fernet import Fernet

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, 'storage')
KEY_FILE = os.path.join(STORAGE_DIR, 'secret.key')


# ---------------------------------------------------------------------------
# Master Key Management
# ---------------------------------------------------------------------------
def load_or_generate_key() -> bytes:
    """
    Load the Fernet master key from disk, or generate a fresh one.

    Fernet keys are 32 bytes of URL-safe base64.  Under the hood the key is
    split into:
      • 16 bytes for AES-128-CBC (confidentiality)
      • 16 bytes for HMAC-SHA256  (authentication / integrity of ciphertext)

    IMPORTANT — In production:
      • Store the key in a KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault).
      • Rotate keys periodically and support key versioning.
      • Never commit secret.key to version control.
    """
    os.makedirs(STORAGE_DIR, exist_ok=True)

    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as key_file:
            key = key_file.read()
    else:
        # Generate a cryptographically random 256-bit key
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
    return key


# ---------------------------------------------------------------------------
# Initialise the cipher suite at module load time
# ---------------------------------------------------------------------------
MASTER_KEY = load_or_generate_key()
cipher_suite = Fernet(MASTER_KEY)


# ---------------------------------------------------------------------------
# Encryption / Decryption Helpers
# ---------------------------------------------------------------------------
def encrypt_file_bytes(plaintext_bytes: bytes) -> bytes:
    """
    Encrypt raw file bytes using Fernet symmetric encryption.

    Security Guarantee:
      Fernet provides *authenticated* encryption — the ciphertext is both
      confidential (AES-CBC) and tamper-evident (HMAC-SHA256).  An attacker
      who modifies even a single byte of the ciphertext will cause decryption
      to fail with an ``InvalidToken`` exception.

    Data Flow:
      plaintext_bytes  ──►  AES-128-CBC encrypt  ──►  HMAC sign  ──►  ciphertext

    Args:
        plaintext_bytes: Raw, unencrypted file content (read from the upload
                         stream — these bytes are held **only in memory**).

    Returns:
        Fernet ciphertext token (bytes), safe to persist on disk.
    """
    return cipher_suite.encrypt(plaintext_bytes)


def decrypt_file_bytes(encrypted_bytes: bytes) -> bytes:
    """
    Decrypt Fernet-encrypted bytes back to plaintext **in memory**.

    CRITICAL SECURITY RULE:
      The returned plaintext must **never** be written to disk.  It is served
      directly to the client via an HTTP response stream so that the Data at
      Rest guarantee is maintained at all times.

    Data Flow:
      ciphertext  ──►  HMAC verify  ──►  AES-128-CBC decrypt  ──►  plaintext (memory only)

    Args:
        encrypted_bytes: The Fernet ciphertext read from the ``.enc`` file.

    Returns:
        The original plaintext bytes.

    Raises:
        cryptography.fernet.InvalidToken: Raised if the master key is wrong
            or if the ciphertext has been tampered with (HMAC mismatch).
    """
    return cipher_suite.decrypt(encrypted_bytes)


# ---------------------------------------------------------------------------
# Cryptographic Hashing (Integrity)
# ---------------------------------------------------------------------------
def calculate_sha256(data: bytes) -> str:
    """
    Compute the SHA-256 digest of arbitrary data.

    Properties of SHA-256:
      • Deterministic   — identical input always yields the same 64-hex-char hash.
      • Avalanche Effect — a 1-bit input change flips ~50 % of output bits.
      • Pre-image Resistant — computationally infeasible to reverse.
      • Collision Resistant — finding two distinct inputs with the same hash
                              is astronomically unlikely.

    Usage in this project (Integrity Verification):
      1. **Upload**:   hash = SHA-256(plaintext)  →  stored in metadata.json
      2. **Download**:  hash' = SHA-256(decrypted) →  compared against stored hash
      3.  hash == hash'  ⇒  file is intact (PASS)
          hash != hash'  ⇒  tampering detected (CRITICAL ALERT)

    Args:
        data: The raw bytes to hash (plaintext file content).

    Returns:
        The hexadecimal string representation of the SHA-256 digest (64 chars).
    """
    return hashlib.sha256(data).hexdigest()
