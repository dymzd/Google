from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sgstudio.providers.google_rest import JsonTransport


class CertificateIssuanceRejectedError(ValueError):
    """The CA authoritatively completed the create operation as failed."""


@dataclass(frozen=True, repr=False)
class CertificateBundle:
    certificate_pem: bytes = field(repr=False)
    certificate_chain_pem: tuple[bytes, ...] = field(repr=False)
    private_key_pem: bytes = field(repr=False)
    fingerprint_sha256: str
    not_after: datetime
    hostname: str
    issuer_resource_name: str | None = None
    csr_sha256: str | None = None
    issuer_certificate_authority: str | None = None

    def secret_payload(self) -> bytes:
        """Serialize only for direct transmission to Secret Manager."""
        return json.dumps(
            {
                "certificate_pem": self.certificate_pem.decode("ascii"),
                "certificate_chain_pem": [
                    certificate.decode("ascii") for certificate in self.certificate_chain_pem
                ],
                "private_key_pem": self.private_key_pem.decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class CertificateIssuer:
    def __init__(
        self,
        transport: JsonTransport | None = None,
        *,
        poll_interval_seconds: float = 1.0,
        operation_timeout_seconds: float = 900.0,
    ) -> None:
        self._transport = transport
        self._poll_interval = poll_interval_seconds
        self._operation_timeout = operation_timeout_seconds

    @staticmethod
    def prepare_enterprise_request(
        hostname: str,
    ) -> tuple[rsa.RSAPrivateKey, bytes]:
        """Generate the key/CSR before a durable ownership checkpoint."""
        return CertificateIssuer._generate_key_and_csr(hostname)

    def issue_enterprise_ca(
        self,
        *,
        hostname: str,
        ca_pool: str,
        ca_name: str,
        certificate_id: str,
        lifetime_days: int,
        request_id: str | None = None,
        request: tuple[rsa.RSAPrivateKey, bytes] | None = None,
    ) -> CertificateBundle:
        if self._transport is None:
            raise RuntimeError("Google REST transport is required for enterprise issuance")
        private_key, csr_pem = request or self._generate_key_and_csr(hostname)
        expected_name = f"{ca_pool}/certificates/{certificate_id}"
        status_code, response = self._transport.request_json(
            "POST",
            f"https://privateca.googleapis.com/v1/{ca_pool}/certificates",
            params={
                "certificateId": certificate_id,
                "issuingCertificateAuthorityId": ca_name.rsplit("/", maxsplit=1)[-1],
                **({"requestId": request_id} if request_id else {}),
            },
            json_body={
                "pemCsr": csr_pem.decode("ascii"),
                "lifetime": f"{lifetime_days * 86400}s",
            },
            accepted_statuses=(200, 409),
        )
        if status_code == 409:
            _, response = self._transport.request_json(
                "GET",
                f"https://privateca.googleapis.com/v1/{expected_name}",
                accepted_statuses=(200,),
            )
        else:
            response = self._resolve_private_ca_operation(response, ca_pool)
        if response.get("name") != expected_name:
            raise ValueError("Private CA returned an unexpected certificate resource")
        if response.get("pemCsr") != csr_pem.decode("ascii"):
            raise ValueError("Private CA returned a certificate for an unexpected CSR")
        if response.get("issuerCertificateAuthority") != ca_name:
            raise ValueError("Private CA returned an unexpected issuing certificate authority")
        certificate_pem = self._required_pem(response, "pemCertificate")
        issuer_resource_name = response.get("name")
        if issuer_resource_name != expected_name:
            raise ValueError("Private CA returned an unexpected certificate resource")
        chain_value = response.get("pemCertificateChain", [])
        if not isinstance(chain_value, list) or not all(
            isinstance(item, str) for item in chain_value
        ):
            raise ValueError("Private CA returned an invalid certificate chain")
        return self._validate_bundle(
            hostname=hostname,
            private_key=private_key,
            certificate_pem=certificate_pem,
            chain=tuple(item.encode("ascii") for item in chain_value),
            issuer_resource_name=issuer_resource_name,
            csr_sha256=hashlib.sha256(csr_pem).hexdigest(),
            issuer_certificate_authority=ca_name,
            expected_lifetime_days=lifetime_days,
            require_chain=True,
        )

    def _resolve_private_ca_operation(
        self,
        payload: dict[str, Any],
        ca_pool: str,
    ) -> dict[str, Any]:
        if self._transport is None:
            raise RuntimeError("Google REST transport is required for enterprise issuance")
        operation_name = payload.get("name")
        location_name = ca_pool.split("/caPools/", maxsplit=1)[0]
        operation_pattern = re.compile(
            rf"^{re.escape(location_name)}/operations/[A-Za-z0-9._~-]+$"
        )
        if (
            not isinstance(operation_name, str)
            or operation_pattern.fullmatch(operation_name) is None
        ):
            return payload
        operation = payload
        deadline = time.monotonic() + self._operation_timeout
        while operation.get("done") is not True:
            if operation.get("done") is True and operation.get("error") is not None:
                raise CertificateIssuanceRejectedError(
                    "Private CA certificate operation failed"
                )
            if operation.get("error") is not None:
                raise ValueError("Private CA certificate operation failed")
            if time.monotonic() >= deadline:
                raise ValueError("Private CA certificate operation timed out")
            if self._poll_interval > 0:
                time.sleep(self._poll_interval)
            _, operation = self._transport.request_json(
                "GET",
                f"https://privateca.googleapis.com/v1/{operation_name}",
                accepted_statuses=(200,),
            )
        if operation.get("error") is not None:
            raise CertificateIssuanceRejectedError(
                "Private CA certificate operation failed"
            )
        response = operation.get("response")
        if not isinstance(response, dict):
            raise ValueError("Private CA operation returned no certificate response")
        return response

    def issue_local_poc(
        self,
        *,
        hostname: str,
        lifetime_days: int = 30,
    ) -> CertificateBundle:
        private_key, csr_pem = self._generate_key_and_csr(hostname)
        csr = x509.load_pem_x509_csr(csr_pem)
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        now = datetime.now(UTC)
        root_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Gateway Studio PoC"),
                x509.NameAttribute(
                    NameOID.COMMON_NAME,
                    f"Secure Gateway Studio PoC Root - {hostname}",
                ),
            ]
        )
        root_certificate = (
            x509.CertificateBuilder()
            .subject_name(root_subject)
            .issuer_name(root_subject)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=lifetime_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
                critical=False,
            )
            .sign(root_key, hashes.SHA256())
        )
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(root_subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=lifetime_days))
            .add_extension(san, critical=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                critical=False,
            )
            .sign(root_key, hashes.SHA256())
        )
        return self._validate_bundle(
            hostname=hostname,
            private_key=private_key,
            certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
            chain=(root_certificate.public_bytes(serialization.Encoding.PEM),),
        )

    @staticmethod
    def validate_secret_payload(
        payload: bytes,
        *,
        hostname: str,
        minimum_validity_days: int = 14,
    ) -> tuple[str, datetime]:
        if len(payload) > 256_000:
            raise ValueError("TLS secret payload exceeds the 256 KB safety limit")
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("TLS secret payload is not valid JSON") from error
        if not isinstance(document, dict):
            raise ValueError("TLS secret payload must be a JSON object")
        certificate_value = document.get("certificate_pem")
        private_key_value = document.get("private_key_pem")
        chain = document.get("certificate_chain_pem")
        if (
            not isinstance(certificate_value, str)
            or not isinstance(private_key_value, str)
            or not isinstance(chain, list)
            or not all(isinstance(item, str) for item in chain)
        ):
            raise ValueError("TLS secret payload does not match the required contract")
        certificate = x509.load_pem_x509_certificate(certificate_value.encode("ascii"))
        private_key = serialization.load_pem_private_key(
            private_key_value.encode("ascii"),
            password=None,
        )
        certificate_public = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_public = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if certificate_public != key_public:
            raise ValueError("TLS secret certificate and private key do not match")
        try:
            sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            dns_names = sans.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound as error:
            raise ValueError("TLS secret certificate is missing a DNS SAN") from error
        if not any(CertificateIssuer._dns_name_matches(hostname, name) for name in dns_names):
            raise ValueError("TLS secret certificate SAN does not match the hostname")
        now = datetime.now(UTC)
        if certificate.not_valid_before_utc > now + timedelta(minutes=1):
            raise ValueError("TLS secret certificate is not yet valid")
        minimum_not_after = now + timedelta(days=minimum_validity_days)
        if certificate.not_valid_after_utc <= minimum_not_after:
            raise ValueError("TLS secret certificate expires too soon")
        try:
            leaf_constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound:
            leaf_constraints = None
        if leaf_constraints is not None and leaf_constraints.ca:
            raise ValueError("TLS secret leaf certificate must not be a CA")

        # Web servers send the leaf followed by zero or more issuer certificates.
        # The operating system/browser trust store is intentionally not consulted
        # here (it is not exposed consistently to either runtime), but every
        # supplied link is still parsed, ordered, time-checked, CA-constrained,
        # and cryptographically verified.  Browser acceptance remains an explicit
        # end-to-end acceptance check against the platform trust store.
        issuers: list[x509.Certificate] = []
        for index, item in enumerate(chain):
            try:
                issuer = x509.load_pem_x509_certificate(item.encode("ascii"))
            except (ValueError, UnicodeEncodeError) as error:
                raise ValueError(
                    f"TLS secret certificate chain entry {index} is not valid PEM"
                ) from error
            if issuer.not_valid_before_utc > now + timedelta(minutes=1):
                raise ValueError("TLS secret certificate chain contains a not-yet-valid issuer")
            if issuer.not_valid_after_utc <= now:
                raise ValueError("TLS secret certificate chain contains an expired issuer")
            try:
                constraints = issuer.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value
            except x509.ExtensionNotFound as error:
                raise ValueError(
                    "TLS secret certificate chain issuer is missing Basic Constraints"
                ) from error
            if not constraints.ca:
                raise ValueError("TLS secret certificate chain issuer is not a CA")
            issuers.append(issuer)

        child = certificate
        for issuer in issuers:
            if child.issuer != issuer.subject:
                raise ValueError("TLS secret certificate chain is not in leaf-to-root order")
            try:
                child.verify_directly_issued_by(issuer)
            except (ValueError, TypeError, InvalidSignature) as error:
                raise ValueError("TLS secret certificate chain signature is invalid") from error
            child = issuer

        # If the supplied chain includes a root, also prove the root's
        # self-signature. A normal TLS chain may omit the public root, in which
        # case the last intermediate is necessarily verified by the browser.
        if issuers and child.issuer == child.subject:
            try:
                child.verify_directly_issued_by(child)
            except (ValueError, TypeError, InvalidSignature) as error:
                raise ValueError(
                    "TLS secret certificate chain root signature is invalid"
                ) from error
        return (
            certificate.fingerprint(hashes.SHA256()).hex(),
            certificate.not_valid_after_utc,
        )

    @staticmethod
    def _dns_name_matches(hostname: str, dns_name: str) -> bool:
        """Match an RFC 6125-style DNS SAN without broad multi-label wildcards."""
        host = hostname.rstrip(".").lower()
        pattern = dns_name.rstrip(".").lower()
        if pattern == host:
            return True
        if not pattern.startswith("*.") or pattern.count("*") != 1:
            return False
        suffix = pattern[2:]
        return (
            bool(suffix)
            and host.endswith(f".{suffix}")
            and host.count(".") == suffix.count(".") + 1
        )

    @staticmethod
    def _generate_key_and_csr(
        hostname: str,
    ) -> tuple[rsa.RSAPrivateKey, bytes]:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        return private_key, csr.public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def _required_pem(response: dict[str, Any], field_name: str) -> bytes:
        value = response.get(field_name)
        if not isinstance(value, str) or "-----BEGIN CERTIFICATE-----" not in value:
            raise ValueError(f"Private CA response is missing {field_name}")
        return value.encode("ascii")

    @staticmethod
    def _validate_bundle(
        *,
        hostname: str,
        private_key: rsa.RSAPrivateKey,
        certificate_pem: bytes,
        chain: tuple[bytes, ...],
        issuer_resource_name: str | None = None,
        csr_sha256: str | None = None,
        issuer_certificate_authority: str | None = None,
        expected_lifetime_days: int | None = None,
        require_chain: bool = False,
    ) -> CertificateBundle:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
        key_public = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        certificate_public = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if key_public != certificate_public:
            raise ValueError("Issued certificate does not match the generated private key")

        try:
            sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            dns_names = sans.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound as error:
            raise ValueError("Issued certificate is missing a DNS SAN") from error
        if hostname not in dns_names:
            raise ValueError("Issued certificate SAN does not match the private hostname")

        now = datetime.now(UTC)
        if certificate.not_valid_before_utc > now + timedelta(minutes=1):
            raise ValueError("Issued certificate is not yet valid")
        if certificate.not_valid_after_utc <= now:
            raise ValueError("Issued certificate is already expired")
        if certificate.not_valid_before_utc < now - timedelta(days=1):
            raise ValueError("Issued certificate validity starts unexpectedly far in the past")
        if expected_lifetime_days is not None:
            requested_not_after = now + timedelta(days=expected_lifetime_days)
            if not (
                requested_not_after - timedelta(days=1)
                <= certificate.not_valid_after_utc
                <= requested_not_after + timedelta(days=1)
            ):
                raise ValueError("Issued certificate validity does not match the request")
        if require_chain and not chain:
            raise ValueError("Issued certificate response is missing its issuer chain")

        private_key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        CertificateIssuer.validate_secret_payload(
            CertificateBundle(
                certificate_pem=certificate_pem,
                certificate_chain_pem=chain,
                private_key_pem=private_key_pem,
                fingerprint_sha256="",
                not_after=certificate.not_valid_after_utc,
                hostname=hostname,
            ).secret_payload(),
            hostname=hostname,
            minimum_validity_days=0,
        )
        return CertificateBundle(
            certificate_pem=certificate_pem,
            certificate_chain_pem=chain,
            private_key_pem=private_key_pem,
            fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
            not_after=certificate.not_valid_after_utc,
            hostname=hostname,
            issuer_resource_name=issuer_resource_name,
            csr_sha256=csr_sha256,
            issuer_certificate_authority=issuer_certificate_authority,
        )
