# Komainu Multi-Tenant SaaS Architecture & BYOK Encryption (Boilerplate 4)

This module provides multi-tenant isolation, cryptographically bound execution context scoping, tamper-evident audit trails, and per-tenant Bring Your Own Key (BYOK) envelope encryption.

---

## 1. Security Invariants & Defense Architecture

### 1.1 Tenant Context Resolution (`middleware/tenant_context.py`)
- **Verified Claim Authority**: Tenant identity is resolved strictly from cryptographically verified token claims (`tenant_id`, `tid`, `tenant`).
- **Internal Service Authentication**: Direct tenant headers (`X-Tenant-ID`) are rejected unless the caller provides valid internal service authentication (`X-Internal-Service-Key` matching `KOMAINU_INTERNAL_SERVICE_SECRET`).
- **Conflict Fail-Closed**: Any discrepancy between verified claims, host subdomains, and authenticated internal headers immediately raises `CrossTenantAccessDeniedError`.
- **Strict Format Validation**: Tenant IDs must strictly match `^[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]$|^[a-z0-9]$` (1-64 characters).

### 1.2 Tamper-Evident Audit Trail (`audit/audit_trail.py`)
- **Keyed Cryptographic Integrity**: Records are hashed using HMAC-SHA256 with `KOMAINU_AUDIT_HMAC_KEY` to prevent unauthorized re-calculation.
- **Canonical Serialization**: Uses deterministic canonical JSON (`separators=(',', ':')`, sorted keys) eliminating delimiter ambiguity.
- **Monotonic Sequence Enforcement**: Records enforce an incrementing `seq` counter (1-indexed) detecting omissions, reordering, and replay.
- **Truncation Detection & Head Anchoring**: Chain heads can be committed via `anchor_head` or externally registered (`register_anchor`), guaranteeing detection if historical entries are truncated.
- **Thread Safety**: All appending and verification operations are protected by thread locks (`threading.Lock()`).

### 1.3 Per-Tenant BYOK & Crypto-Shredding (`crypto/byok_manager.py`)
- **AES-256-GCM Envelope Encryption**: Sensitive fields are encrypted using ephemeral Data Encryption Keys (DEKs) wrapped by dedicated 256-bit Tenant Master Keys.
- **Key Length Validation**: Master keys must be exactly 32 bytes (256 bits).
- **Permanent Crypto-Shredding**: Revoking a tenant key permanently prevents decryption and strictly blocks any future re-registration of that tenant (`TenantKeyRevokedError`).
