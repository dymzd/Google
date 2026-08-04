from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sgstudio.providers.certificates import CertificateIssuer


class FakePrivateCaTransport:
    def __init__(self) -> None:
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Enterprise Test CA")])

    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        del accepted_statuses
        assert method == "POST"
        assert url.endswith("/certificates")
        assert params == {"certificateId": "gateway-server"}
        assert json_body is not None
        csr = x509.load_pem_x509_csr(json_body["pemCsr"].encode())
        now = datetime.now(UTC)
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.ca_name)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(san, critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        return 200, {
            "pemCertificate": certificate.public_bytes(serialization.Encoding.PEM).decode(),
            "pemCertificateChain": [],
        }


def test_local_poc_certificate_has_matching_key_and_san() -> None:
    bundle = CertificateIssuer().issue_local_poc(hostname="demo.internal")
    payload = bundle.secret_payload()

    assert bundle.hostname == "demo.internal"
    assert len(bundle.fingerprint_sha256) == 64
    assert len(bundle.certificate_chain_pem) == 1
    leaf = x509.load_pem_x509_certificate(bundle.certificate_pem)
    root = x509.load_pem_x509_certificate(bundle.certificate_chain_pem[0])
    assert leaf.issuer == root.subject
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    root.public_key().verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        leaf.signature_algorithm_parameters,
        leaf.signature_hash_algorithm,
    )
    assert b'"private_key_pem":"-----BEGIN PRIVATE KEY-----' in payload
    assert "PRIVATE KEY" not in repr(bundle)


def test_enterprise_ca_issuance_validates_returned_certificate() -> None:
    bundle = CertificateIssuer(FakePrivateCaTransport()).issue_enterprise_ca(
        hostname="demo.internal",
        ca_pool="projects/p/locations/asia-east1/caPools/enterprise",
        ca_name=(
            "projects/p/locations/asia-east1/caPools/enterprise/certificateAuthorities/issuing"
        ),
        certificate_id="gateway-server",
        lifetime_days=90,
    )

    assert bundle.hostname == "demo.internal"
    assert bundle.not_after > datetime.now(UTC)


def test_secret_contract_validation_checks_key_san_and_validity() -> None:
    bundle = CertificateIssuer().issue_local_poc(
        hostname="demo-server-http.internal",
        lifetime_days=30,
    )

    fingerprint, not_after = CertificateIssuer.validate_secret_payload(
        bundle.secret_payload(),
        hostname="demo-server-http.internal",
        minimum_validity_days=1,
    )

    assert fingerprint == bundle.fingerprint_sha256
    assert not_after == bundle.not_after


def test_secret_contract_rejects_wrong_hostname() -> None:
    bundle = CertificateIssuer().issue_local_poc(
        hostname="demo-server-http.internal",
        lifetime_days=30,
    )

    with pytest.raises(ValueError, match="SAN"):
        CertificateIssuer.validate_secret_payload(
            bundle.secret_payload(),
            hostname="other.internal",
            minimum_validity_days=1,
        )
