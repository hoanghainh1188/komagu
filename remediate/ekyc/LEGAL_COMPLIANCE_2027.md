# Legal Review & Compliance Analysis: Japan 2027 eKYC Amendments
## 犯罪収益移転防止法施行規則改正（2027年4月1日施行）およびゼロPII設計検証

- **Legislation**: Act on Prevention of Transfer of Criminal Proceeds (犯罪による収益の移転防止に関する法律 / 犯収法)
- **Regulatory Body**: National Police Agency of Japan (警察庁 / NPA)
- **Promulgation Date**: 2024-06-25 (Order of NPA No. 5 of 2024)
- **Effective Enforcement Date**: **2027-04-01**
- **Document Reference**: Komainu Boilerplate 2 (Zero-PII eKYC & NFC Verification)
- **Reviewed by**: Harry Nguyen (Principal Architect / BOD / BrSE) & Komainu Legal Engineering

---

## 1. Regulatory Background: The Abolition of Photo-Upload eKYC

Historically under Article 6, Paragraph 1, Item 1 of the Enforcement Regulations of the Act on Prevention of Transfer of Criminal Proceeds:
- **Legacy Method "He" (規則第6条第1項第1号「ヘ」):** Allowed remote identity verification by requiring users to transmit photos of their physical ID document (front, back, and thickness/oblique angle) alongside a facial photo (selfie or liveness detection).
- **The Vulnerability & Incident Driver:**
  - Photo-based verification became acutely vulnerable to generative AI deepfakes, manipulated image layers, and stolen physical ID documents traded on darknet forums.
  - Furthermore, businesses storing raw photographic scans of identification documents became prime targets for mass breaches (e.g., the September 2025 Times Car incident involving unauthorized access to 6.6 million accounts, exposing driver license and ID scans).
- **The 2027 Regulatory Change (2027年4月1日施行):**
  - The National Police Agency amended the ordinance to **abolish legacy photo-upload verification (ホ・ヘ方式の画像アップロード)** for opening new financial, telecom, and verified transaction accounts.
  - Only **cryptographic IC chip reading** and **JPKI (Japanese Public Key Infrastructure)** are legally recognized as compliant remote verification methods.

---

## 2. Permitted Verification Methods Under the 2027 Regime

Under the revised enforcement framework taking effect in April 2027, remote non-face-to-face identity verification is restricted to:

| Method Code | Regulatory Clause | Verification Mechanism | Required Hardware / Data | Komainu BP2 Architecture |
|---|---|---|---|---|
| **Ho (ホ方式)** | 第6条第1項第1号「ホ」 | **JPKI (Public Personal Authentication Service / 公的個人認証サービス)** using My Number Card IC chip | Smartphone NFC reader + JPKI User Authentication Certificate (署名用／利用者証明用電子証明書) | **Primary Supported Flow**: Direct NFC reading of My Number Card with J-LIS CA signature verification. |
| **He (新ヘ方式)** | 第6条第1項第1号「新ヘ」 | **IC Chip Reading + Facial Biometric Match**: Reading the cryptographic data from the IC chip of a Driver's License, Residence Card, or My Number Card + Liveness match against chip photo | Smartphone NFC reader + PIN1/PIN2 + Secure Enclave biometric liveness match | **Secondary Flow**: Cryptographic signature validation on IC chip SOD (Security Object Document). |
| **To (ト方式)** | 第6条第1項第1号「ト」 | Bank API / Transfer Verification + Identity Document | Existing verified bank account query | Out of scope for client-side NFC. |

---

## 3. Komainu "Zero-PII" Architecture & Threat Model

To eliminate the systemic risk of massive PII data leaks, Boilerplate 2 enforces an architectural invariant: **ZERO RAW ID IMAGES STORED ON SERVER (生画像非保持化)**.

```
+──────────────────────────────────────────────────────────────────────────────────────────────────+
|                                    ZERO-PII eKYC VERIFICATION FLOW                               |
+──────────────────────────────────────────────────────────────────────────────────────────────────+
|                                                                                                  |
|   1. Mobile Client (NFC)               2. Komainu Gateway                 3. J-LIS / IdP Root    |
|   ┌────────────────────┐               ┌────────────────────┐            ┌────────────────────┐  |
|   │ • Read IC Chip via │ ──Nonce Req─> │ • Issue Replay-    │            │                    │  |
|   │   ISO/IEC 7816-4   │ <──Nonce───── │   Resistant Nonce  │            │                    │  |
|   │ • Sign Nonce with  │               └────────────────────┘            │                    │  |
|   │   JPKI Private Key │ ──Payload───> ┌────────────────────┐            │                    │  |
|   │ • NO RAW IMAGES!   │ (Cert+Sig+    │ • Validate JPKI    │ ──Verify─> │ • Check CRL &      │  |
|   │                    │  Tokenized)   │   Signature & Cert │ <─Chain─── │   J-LIS Trust Root │  |
|   └────────────────────┘               │ • Reject Raw Image │            └────────────────────┘  |
|                                        │ • Blind Tokenize   │                                    |
|                                        │ • Issue Verified   │                                    |
|                                        │   Identity Token   │                                    |
|                                        └────────────────────┘                                    |
+──────────────────────────────────────────────────────────────────────────────────────────────────+
```

### Invariant Rules:
1. **Rule ZPII-01 (Strict Image Rejection)**: Any request payload containing image data (MIME `image/*`, base64 image strings, or JPEG/PNG byte headers) is immediately rejected with HTTP `422 Unprocessable Entity`.
2. **Rule ZPII-02 (Ephemeral Memory Processing)**: Name, date of birth, and address extracted during cryptographic verification are held in volatile memory only for the duration of the signature validation transaction (max 30 seconds).
3. **Rule ZPII-03 (Blind Index Tokenization)**: Permanent database storage retains only:
   - `identity_token`: Cryptographically signed JWT issued by Komainu.
   - `blind_hash`: Salted HMAC-SHA256 hash of the verified identity for deduplication (preventing duplicate account creation without storing raw identifiers).
   - `verification_timestamp` and `jlis_cert_serial_hash`.

---

## 4. Verification Checkpoint for Enterprise Audit

This document confirms that Komainu Boilerplate 2 satisfies:
- Japan National Police Agency Order No. 5 (2024)
- Digital Agency Guidelines for JPKI Integration (デジタル庁 公的個人認証サービス技術仕様)
- Act on the Protection of Personal Information (個人情報の保護に関する法律 - APPI)

---

## 5. Scope & Production J-LIS Integration Notice

> [!NOTE]
> **Reference Architecture & Test Harness Scope**:
> Komainu Boilerplate 2 provides the reference client-side Zero-PII tokenization patterns, ISO/IEC 7816-4 APDU sequences, and cryptographic verification contracts.
> 
> Direct connectivity to J-LIS (地方公共団体情報システム機構) in production requires:
> 1. Formal accreditation under the Public Personal Authentication Act as a certified verification business (大臣認定事業者) or integration through an authorized JPKI platform operator.
> 2. Dedicated leased-line / IPsec VPN connectivity or certified mTLS gateway to the J-LIS certificate validation endpoints.
> 3. Production deployments must run in non-simulation mode with valid X.509 certificates and strict CRL/OCSP revocation checks.
>
> **What the code enforces (fail-closed defaults):**
> - `JPKIVerificationEngine` rejects every certificate unless J-LIS trust anchors (`trusted_certs`) **and** a revocation checker (`crl_checker`) are configured; the chain check is never skipped, and only CA certificates with RSA/ECDSA keys are accepted as issuers.
> - Token attributes come only from the verified credential: the certificate CN (`name`) plus SubjectAltName otherName values mapped via `attribute_oids` to the J-LIS certificate profile. A client-claimed attribute that the credential does not carry is rejected.
> - Driver-licence SODs are rejected unless a real `sod_verifier` (DS certificate chain to the CSCA and data-group hashes) is injected; structural checks alone never pass.
> - The sha256 simulation harness runs only when `KOMAINU_EKYC_SIMULATION=1` is set explicitly. It is never inferred from `CI`, `KOMAINU_ENV` or loaded test frameworks — do not set this variable in any deployed environment.

