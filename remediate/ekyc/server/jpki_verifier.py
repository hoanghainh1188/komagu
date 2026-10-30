#!/usr/bin/env python3
"""JPKI (Japanese Public Key Infrastructure) Backend Verification Engine.

Validates digital signatures, X.509 certificate chains, validity periods, and CRL revocations
issued by J-LIS (地方公共団体情報システム機構) under the Act on Public Personal Authentication Service
(電子署名等に係る地方公共団体情報システム機構の認証業務に関する法律).
"""

from __future__ import annotations

import collections
import datetime
import hashlib
import hmac
import os
import secrets
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    """Read KOMAGU_<name>."""
    return os.environ.get("KOMAGU_" + name, default)


try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

MAX_ACTIVE_NONCES = 1000

# Simulation (signature = sha256("JPKI-SE-KEY:" + nonce), computable by anyone) is only
# allowed when this variable is exactly "1". It is never inferred from CI, KOMAGU_ENV
# or imported test frameworks: a production container can easily carry any of those.
SIMULATION_ENV_FLAG = "KOMAGU_EKYC_SIMULATION"

# Verifies a driver-licence SOD (CMS SignedData: DS certificate chain to the CSCA and
# data-group hashes). Returns (ok, message, attributes read from the verified data groups).
SODVerifier = Callable[[bytes], Tuple[bool, str, Dict[str, str]]]


class NonceStoreCapacityExceededError(RuntimeError):
    """Raised when active unexpired nonces reach capacity limit."""
    pass


class NonceRateLimitExceededError(PermissionError):
    """Raised when a client exceeds challenge request rate limit."""
    pass


class BaseNonceStore:
    """Abstract base class for challenge nonce storage."""

    def generate_and_store(self, ttl_seconds: int = 300, client_id: Optional[str] = None) -> str:
        raise NotImplementedError

    def validate_and_consume(self, nonce: str) -> bool:
        raise NotImplementedError


class InMemoryNonceStore(BaseNonceStore):
    """Thread-safe, capacity-guarded, rate-limited in-memory challenge nonce store."""

    def __init__(
        self,
        max_active_nonces: int = 1000,
        rate_limit_per_client: int = 20,
        rate_limit_window_seconds: int = 60,
        evict_on_capacity: bool = True,
    ):
        self.max_active_nonces = max_active_nonces
        self.rate_limit_per_client = rate_limit_per_client
        self.rate_limit_window_seconds = rate_limit_window_seconds
        self.evict_on_capacity = evict_on_capacity
        self._lock = threading.Lock()
        self._nonces: collections.OrderedDict[str, float] = collections.OrderedDict()  # {nonce: expiry_timestamp}
        self._client_requests: Dict[str, List[float]] = {}  # {client_id: [timestamps]}

    def _clean_expired(self, now: float) -> None:
        """Purge expired nonces and stale rate limit timestamps."""
        expired = [n for n, exp in self._nonces.items() if exp <= now]
        for n in expired:
            del self._nonces[n]

        cutoff = now - self.rate_limit_window_seconds
        stale_clients = []
        for cid, timestamps in self._client_requests.items():
            valid_ts = [t for t in timestamps if t > cutoff]
            if valid_ts:
                self._client_requests[cid] = valid_ts
            else:
                stale_clients.append(cid)
        for cid in stale_clients:
            del self._client_requests[cid]

    def generate_and_store(self, ttl_seconds: int = 300, client_id: Optional[str] = None) -> str:
        with self._lock:
            now = time.time()
            self._clean_expired(now)

            # Per-client rate limiting
            cid = client_id or "anonymous"
            client_history = self._client_requests.setdefault(cid, [])
            if len(client_history) >= self.rate_limit_per_client:
                raise NonceRateLimitExceededError(
                    f"Rate limit exceeded: client '{cid}' has issued {len(client_history)} challenges "
                    f"in the last {self.rate_limit_window_seconds}s (limit: {self.rate_limit_per_client})."
                )

            # Capacity limit handling
            if len(self._nonces) >= self.max_active_nonces:
                if self.evict_on_capacity:
                    self._nonces.popitem(last=False)
                else:
                    raise NonceStoreCapacityExceededError(
                        f"Nonce store capacity ({self.max_active_nonces}) reached with active unexpired nonces. "
                        "Rejecting new challenges to protect pending verification sessions."
                    )

            nonce = secrets.token_hex(32)
            self._nonces[nonce] = now + ttl_seconds
            client_history.append(now)
            return nonce

    def validate_and_consume(self, nonce: str) -> bool:
        with self._lock:
            now = time.time()
            self._clean_expired(now)
            if nonce not in self._nonces:
                return False
            expiry = self._nonces.pop(nonce)
            return now <= expiry


class RedisNonceStore(BaseNonceStore):
    """Shared Redis-backed challenge nonce store for multi-replica production deployments."""

    def __init__(
        self,
        redis_client: Any,
        key_prefix: str = "komagu:ekyc:nonce:",
        rate_limit_per_client: int = 20,
        rate_limit_window_seconds: int = 60,
    ):
        self.redis = redis_client
        self.key_prefix = key_prefix
        self.rate_limit_per_client = rate_limit_per_client
        self.rate_limit_window_seconds = rate_limit_window_seconds

    def generate_and_store(self, ttl_seconds: int = 300, client_id: Optional[str] = None) -> str:
        cid = client_id or "anonymous"
        rl_key = f"{self.key_prefix}rl:{cid}"
        req_count = self.redis.incr(rl_key)
        if req_count == 1:
            self.redis.expire(rl_key, self.rate_limit_window_seconds)
        if req_count > self.rate_limit_per_client:
            raise NonceRateLimitExceededError(
                f"Rate limit exceeded: client '{cid}' has exceeded {self.rate_limit_per_client} challenges."
            )

        nonce = secrets.token_hex(32)
        key = f"{self.key_prefix}{nonce}"
        self.redis.setex(key, ttl_seconds, "1")
        return nonce

    def validate_and_consume(self, nonce: str) -> bool:
        key = f"{self.key_prefix}{nonce}"
        if hasattr(self.redis, "getdel"):
            val = self.redis.getdel(key)
        else:
            lua = """
            local val = redis.call('GET', KEYS[1])
            if val then
                redis.call('DEL', KEYS[1])
                return val
            else
                return nil
            end
            """
            val = self.redis.eval(lua, 1, key)
        return val is not None


def _simulation_opted_in() -> bool:
    """True only when simulation was explicitly enabled for this process."""
    return _env("EKYC_SIMULATION", "") == "1"


def _check_attribute_binding(claimed: Optional[Dict[str, Any]], verified: Dict[str, str]) -> Optional[str]:
    """Return an error when a client-claimed attribute is absent from, or differs from, verified data."""
    for key, value in (claimed or {}).items():
        if key not in verified:
            return f"Attribute '{key}' is not bound to the verified credential and cannot be accepted"
        if verified[key] != value:
            return (
                f"Attribute binding mismatch: verified '{key}' '{verified[key]}' "
                f"does not match claimed value '{value}'"
            )
    return None


def _decode_der_utf8_string(der: bytes) -> Optional[str]:
    """Decode a DER UTF8String (tag 0x0C) as stored in a SubjectAltName otherName value."""
    if len(der) < 2 or der[0] != 0x0C:
        return None
    length, offset = der[1], 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or len(der) < 2 + n:
            return None
        length, offset = int.from_bytes(der[2:2 + n], "big"), 2 + n
    if len(der) != offset + length:
        return None
    try:
        return der[offset:].decode("utf-8")
    except UnicodeDecodeError:
        return None


class JPKIVerificationEngine:
    """Verifies JPKI digital signatures, certificate chains, and challenge nonces."""

    def __init__(
        self,
        trust_anchor: str = "J-LIS-Root-CA",
        max_active_nonces: int = MAX_ACTIVE_NONCES,
        allow_simulation: bool = False,
        trusted_certs: Optional[List[x509.Certificate]] = None,
        crl_checker: Optional[Callable[[int], bool]] = None,
        attribute_oids: Optional[Dict[str, str]] = None,
        sod_verifier: Optional[SODVerifier] = None,
        nonce_store: Optional[BaseNonceStore] = None,
        redis_client: Optional[Any] = None,
    ):
        """
        trusted_certs: J-LIS root / intermediate certificates. Required: certificates are
            rejected when none are configured.
        crl_checker: returns True for a revoked serial. Required for the same reason.
        attribute_oids: attribute name -> SubjectAltName otherName OID holding that
            attribute in the signing certificate (the CN is always read as "name").
        sod_verifier: real driver-licence SOD verification; without it SODs are rejected.
        nonce_store: optional pluggable nonce store (Redis, in-memory, etc.).
        redis_client: optional Redis connection for shared multi-replica nonce state.
        """
        self.trust_anchor = trust_anchor
        self.max_active_nonces = max_active_nonces
        self.allow_simulation = allow_simulation
        self.trusted_certs = trusted_certs or []
        self.crl_checker = crl_checker
        self.attribute_oids = dict(attribute_oids or {})
        self.sod_verifier = sod_verifier

        if self.allow_simulation and not _simulation_opted_in():
            raise RuntimeError(
                f"Simulation mode requires {SIMULATION_ENV_FLAG}=1; it is never enabled implicitly."
            )

        # Pluggable challenge nonce storage (thread-safe in-memory or Redis)
        if nonce_store is not None:
            self.nonce_store = nonce_store
        elif redis_client is not None:
            self.nonce_store = RedisNonceStore(redis_client=redis_client)
        else:
            self.nonce_store = InMemoryNonceStore(max_active_nonces=max_active_nonces)

    @property
    def _active_nonces(self) -> Dict[str, float]:
        """Backward-compatible view of active nonces for in-memory storage."""
        if isinstance(self.nonce_store, InMemoryNonceStore):
            return self.nonce_store._nonces
        return {}

    def generate_challenge(self, ttl_seconds: int = 300, client_id: Optional[str] = None) -> str:
        """Issue a cryptographically secure, time-limited challenge nonce."""
        return self.nonce_store.generate_and_store(ttl_seconds=ttl_seconds, client_id=client_id)

    def validate_nonce(self, nonce: str) -> bool:
        """Validate and immediately consume single-use challenge nonce."""
        return self.nonce_store.validate_and_consume(nonce)

    def verify_signature(
        self,
        challenge_nonce: str,
        signature_hex: str,
        document_type: str = "my_number",
        certificate_pem: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """Verify the cryptographic signature against the active challenge nonce."""
        ok, msg, _ = self.verify_identity(
            challenge_nonce, signature_hex, document_type, certificate_pem, attributes
        )
        return ok, msg

    def extract_certificate_attributes(self, cert: "x509.Certificate") -> Dict[str, str]:
        """Identity attributes carried by the verified certificate itself."""
        attrs: Dict[str, str] = {}
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn:
            attrs["name"] = cn[0].value
        if self.attribute_oids:
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            except x509.ExtensionNotFound:
                return attrs
            by_oid = {}
            for other in san.get_values_for_type(x509.OtherName):
                value = _decode_der_utf8_string(other.value)
                if value is not None:
                    by_oid[other.type_id.dotted_string] = value
            for name, oid in self.attribute_oids.items():
                if oid in by_oid:
                    attrs[name] = by_oid[oid]
        return attrs

    def _issuer_signed(self, cert: "x509.Certificate") -> bool:
        """True when a configured CA certificate verifiably signed `cert`."""
        for parent in self.trusted_certs:
            if cert.issuer != parent.subject:
                continue
            try:
                if not parent.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                    continue
            except x509.ExtensionNotFound:
                continue
            parent_pub = parent.public_key()
            try:
                if isinstance(parent_pub, rsa.RSAPublicKey):
                    parent_pub.verify(
                        cert.signature, cert.tbs_certificate_bytes,
                        padding.PKCS1v15(), cert.signature_hash_algorithm,
                    )
                elif isinstance(parent_pub, ec.EllipticCurvePublicKey):
                    parent_pub.verify(
                        cert.signature, cert.tbs_certificate_bytes,
                        ec.ECDSA(cert.signature_hash_algorithm),
                    )
                else:
                    # Unsupported key type: never treat as verified.
                    continue
                return True
            except Exception:
                continue
        return False

    def verify_identity(
        self,
        challenge_nonce: str,
        signature_hex: str,
        document_type: str = "my_number",
        certificate_pem: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str, Dict[str, str]]:
        """Verify the signature and return the attributes the verified credential vouches for.

        Client-claimed `attributes` must each be present in, and equal to, the verified
        attributes; tokens should be built from the returned attributes only.
        """
        # Replay prevention check
        if not self.validate_nonce(challenge_nonce):
            return False, "Invalid or expired challenge nonce (replay attack prevented)", {}

        if not signature_hex or len(signature_hex) < 32:
            return False, "Malformed signature payload", {}

        try:
            signature_bytes = bytes.fromhex(signature_hex)
        except ValueError:
            return False, "Malformed signature payload: invalid hex encoding", {}

        nonce_data = challenge_nonce.encode("utf-8")

        # Mode A: Cryptographic X.509 Verification with attribute binding & CRL check
        if certificate_pem:
            if not HAS_CRYPTOGRAPHY:
                return False, "Cryptographic verification unavailable: 'cryptography' library required", {}
            if not self.trusted_certs:
                return False, "No J-LIS trust anchors configured: refusing to accept any certificate", {}
            if self.crl_checker is None:
                return False, "Certificate revocation checking is not configured: refusing to accept any certificate", {}

            try:
                cert = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
            except Exception as e:
                return False, f"Invalid certificate format: {e}", {}

            # 1. Certificate Validity Period Check
            now = datetime.datetime.now(datetime.timezone.utc)
            try:
                nb = cert.not_valid_before_utc
                na = cert.not_valid_after_utc
            except AttributeError:
                nb = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
                na = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

            if now < nb:
                return False, "Certificate is not yet valid (validity date in future)", {}
            if now > na:
                return False, "Certificate has expired", {}

            # 2. Revocation Check via CRL
            if self.crl_checker(cert.serial_number):
                return False, f"Certificate serial {cert.serial_number} has been revoked (CRL check failed)", {}

            # 3. Chain of Trust Verification (never skipped)
            if not self._issuer_signed(cert):
                return False, "Untrusted certificate: issuer signature verification failed against trusted root", {}

            # 4. Attribute Binding: only attributes carried by the certificate are accepted
            verified_attributes = self.extract_certificate_attributes(cert)
            binding_error = _check_attribute_binding(attributes, verified_attributes)
            if binding_error:
                return False, binding_error, {}

            # 5. Leaf Certificate Constraints: BasicConstraints & KeyUsage (Issue #213)
            try:
                bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
                if bc.ca:
                    return False, "Leaf certificate violation: CA certificate cannot be presented as user leaf certificate", {}
            except x509.ExtensionNotFound:
                pass

            try:
                ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
                if not (ku.digital_signature or ku.content_commitment):
                    return False, "Leaf certificate key usage violation: digital_signature or content_commitment required", {}
                if ku.key_cert_sign or ku.crl_sign:
                    return False, "Leaf certificate key usage violation: user leaf certificate must not possess key_cert_sign or crl_sign", {}
            except x509.ExtensionNotFound:
                return False, "Leaf certificate violation: KeyUsage extension is mandatory", {}

            # 6. Asymmetric Signature Verification
            pub_key = cert.public_key()
            try:
                if isinstance(pub_key, rsa.RSAPublicKey):
                    pub_key.verify(signature_bytes, nonce_data, padding.PKCS1v15(), hashes.SHA256())
                elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                    pub_key.verify(signature_bytes, nonce_data, ec.ECDSA(hashes.SHA256()))
                else:
                    return False, "Unsupported public key algorithm in certificate", {}
            except InvalidSignature:
                return False, "Signature verification failed: cryptographic signature does not match public key", {}

            return True, "JPKI digital signature successfully verified against J-LIS Trust Anchor", verified_attributes

        # Mode B: Simulation (explicit opt-in only)
        if self.allow_simulation:
            if not _simulation_opted_in():
                raise RuntimeError(
                    f"Simulation mode requires {SIMULATION_ENV_FLAG}=1; it is never enabled implicitly."
                )
            expected = hashlib.sha256(b"JPKI-SE-KEY:" + nonce_data).digest()
            if not hmac.compare_digest(signature_bytes, expected):
                return False, "Signature verification failed: cryptographic signature does not match public key", {}
            return True, "Simulated JPKI signature verified (TEST HARNESS ONLY)", dict(attributes or {})

        return False, "Verification requires a valid certificate_pem (simulation mode is disabled)", {}

    def verify_driver_license_sod(self, sod_bytes: bytes) -> Tuple[bool, str]:
        """Verify a Japanese driver-licence Security Object Document (SOD)."""
        ok, msg, _ = self.verify_driver_license(sod_bytes)
        return ok, msg

    def verify_driver_license(self, sod_bytes: bytes) -> Tuple[bool, str, Dict[str, str]]:
        """Verify a driver-licence SOD and return the attributes from its verified data groups.

        Structural checks alone prove nothing, so this fails closed unless a real
        `sod_verifier` (DS certificate chain to the CSCA + data-group hashes) is configured.
        """
        if not sod_bytes or len(sod_bytes) < 32:
            return False, "Invalid Driver License SOD payload: minimum 32 bytes required", {}
        if sod_bytes[0] != 0x30:
            return False, "Invalid Driver License SOD payload: not an ASN.1 DER sequence", {}
        if self.sod_verifier is None:
            return False, (
                "Driver License SOD signature verification is not configured: inject a sod_verifier "
                "that checks the DS certificate chain and data-group hashes"
            ), {}
        return self.sod_verifier(sod_bytes)


class MockJPKIVerificationEngine(JPKIVerificationEngine):
    """Test double for JPKI verification engine with mock J-LIS CA and CRL support."""

    def __init__(
        self,
        trust_anchor: str = "Mock-J-LIS-Root-CA",
        max_active_nonces: int = MAX_ACTIVE_NONCES,
        ca: Optional[Any] = None,
        nonce_store: Optional[BaseNonceStore] = None,
    ):
        trusted_certs = []
        crl_checker = None
        self.ca = ca
        if self.ca is None and HAS_CRYPTOGRAPHY:
            try:
                from remediate.ekyc.server.mock_jlis_ca import MockJLISCertificateAuthority
                self.ca = MockJLISCertificateAuthority()
            except Exception:
                self.ca = None

        attribute_oids: Dict[str, str] = {}
        if self.ca is not None:
            trusted_certs = [self.ca.root_cert, self.ca.sub_cert]
            crl_checker = self.ca.is_revoked
            from remediate.ekyc.server.mock_jlis_ca import MOCK_ATTRIBUTE_OIDS
            attribute_oids = dict(MOCK_ATTRIBUTE_OIDS)

        super().__init__(
            trust_anchor=trust_anchor,
            max_active_nonces=max_active_nonces,
            # Simulated signatures are accepted only when explicitly opted in.
            allow_simulation=_simulation_opted_in(),
            trusted_certs=trusted_certs,
            crl_checker=crl_checker,
            attribute_oids=attribute_oids,
            nonce_store=nonce_store,
        )
