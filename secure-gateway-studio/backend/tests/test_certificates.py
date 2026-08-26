import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sgstudio.providers.certificates import CertificateIssuer


class FakePrivateCaTransport:
    def __init__(self, *, tamper: str | None = None) -> None:
        self.tamper = tamper
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Enterprise Test CA")])
        now = datetime.now(UTC)
        self.ca_certificate = (
            x509.CertificateBuilder()
            .subject_name(self.ca_name)
            .issuer_name(self.ca_name)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )
        self.last_params: dict[str, str | int] | None = None

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
        assert params is not None
        assert params["certificateId"] == "gateway-server"
        assert params["issuingCertificateAuthorityId"] == "issuing"
        self.last_params = params
        assert json_body is not None
        csr = x509.load_pem_x509_csr(json_body["pemCsr"].encode())
        now = datetime.now(UTC)
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if self.tamper == "wrong-san":
            san = x509.SubjectAlternativeName([x509.DNSName("other.internal")])
        public_key = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
            if self.tamper == "wrong-key"
            else csr.public_key()
        )
        not_before = (
            now + timedelta(hours=1)
            if self.tamper == "future"
            else now - timedelta(minutes=1)
        )
        not_after = (
            now + timedelta(days=10)
            if self.tamper == "short-lifetime"
            else now + timedelta(days=90)
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.ca_name)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(san, critical=False)
            .add_extension(
                x509.BasicConstraints(
                    ca=self.tamper == "ca-leaf",
                    path_length=None,
                ),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )
        chain_certificate = self.ca_certificate
        if self.tamper == "wrong-chain-signature":
            other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            chain_certificate = (
                x509.CertificateBuilder()
                .subject_name(self.ca_name)
                .issuer_name(self.ca_name)
                .public_key(other_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .sign(other_key, hashes.SHA256())
            )
        response = {
            "name": (
                "projects/p/locations/asia-east1/caPools/enterprise/"
                "certificates/gateway-server"
            ),
            "pemCsr": json_body["pemCsr"],
            "pemCertificate": certificate.public_bytes(serialization.Encoding.PEM).decode(),
            "pemCertificateChain": [
                chain_certificate.public_bytes(serialization.Encoding.PEM).decode()
            ],
            "issuerCertificateAuthority": (
                "projects/p/locations/asia-east1/caPools/enterprise/"
                "certificateAuthorities/issuing"
            ),
        }
        if self.tamper == "missing-chain":
            response["pemCertificateChain"] = []
        elif self.tamper == "missing-name":
            response.pop("name")
        elif self.tamper == "empty-name":
            response["name"] = ""
        elif self.tamper == "wrong-name":
            response["name"] = (
                "projects/p/locations/asia-east1/caPools/enterprise/"
                "certificates/other"
            )
        elif self.tamper == "wrong-issuer-resource":
            response["issuerCertificateAuthority"] = (
                "projects/p/locations/asia-east1/caPools/enterprise/"
                "certificateAuthorities/other"
            )
        return 200, response


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
    transport = FakePrivateCaTransport()
    bundle = CertificateIssuer(transport).issue_enterprise_ca(
        hostname="demo.internal",
        ca_pool="projects/p/locations/asia-east1/caPools/enterprise",
        ca_name=(
            "projects/p/locations/asia-east1/caPools/enterprise/certificateAuthorities/issuing"
        ),
        certificate_id="gateway-server",
        lifetime_days=90,
        request_id="11111111-1111-4111-8111-111111111111",
    )

    assert bundle.hostname == "demo.internal"
    assert bundle.not_after > datetime.now(UTC)
    assert transport.last_params == {
        "certificateId": "gateway-server",
        "issuingCertificateAuthorityId": "issuing",
        "requestId": "11111111-1111-4111-8111-111111111111",
    }


def test_enterprise_ca_issuance_waits_for_operation_response() -> None:
    class LroTransport(FakePrivateCaTransport):
        def __init__(self) -> None:
            super().__init__()
            self.result: dict[str, Any] | None = None
            self.polls = 0

        def request_json(self, method: str, url: str, **kwargs):
            if method == "POST":
                _, self.result = super().request_json(method, url, **kwargs)
                return 200, {
                    "name": "projects/p/locations/asia-east1/operations/issue-one",
                    "done": False,
                }
            self.polls += 1
            assert url.endswith("/operations/issue-one")
            return 200, {
                "name": "projects/p/locations/asia-east1/operations/issue-one",
                "done": True,
                "response": self.result,
            }

    transport = LroTransport()
    bundle = CertificateIssuer(
        transport,
        poll_interval_seconds=0,
        operation_timeout_seconds=1,
    ).issue_enterprise_ca(
        hostname="demo.internal",
        ca_pool="projects/p/locations/asia-east1/caPools/enterprise",
        ca_name=(
            "projects/p/locations/asia-east1/caPools/enterprise/"
            "certificateAuthorities/issuing"
        ),
        certificate_id="gateway-server",
        lifetime_days=90,
    )

    assert transport.polls == 1
    assert bundle.issuer_resource_name.endswith("/certificates/gateway-server")


@pytest.mark.parametrize(
    "operation_name",
    [
        "projects/other/locations/asia-east1/operations/issue-one",
        "projects/p/locations/us-east1/operations/issue-one",
        "projects/p/locations/asia-east1/operations/../operations/issue-one",
        "projects/p/locations/asia-east1/operations/issue-one?alt=json",
    ],
)
def test_enterprise_ca_issuance_never_polls_an_unbound_operation_name(
    operation_name: str,
) -> None:
    class InvalidLroTransport(FakePrivateCaTransport):
        def __init__(self) -> None:
            super().__init__()
            self.gets = 0

        def request_json(self, method: str, url: str, **kwargs):
            if method == "POST":
                return 200, {"name": operation_name, "done": False}
            self.gets += 1
            raise AssertionError("unbound operation name was polled")

    transport = InvalidLroTransport()

    with pytest.raises(ValueError, match="unexpected certificate resource"):
        CertificateIssuer(transport, poll_interval_seconds=0).issue_enterprise_ca(
            hostname="demo.internal",
            ca_pool="projects/p/locations/asia-east1/caPools/enterprise",
            ca_name=(
                "projects/p/locations/asia-east1/caPools/enterprise/"
                "certificateAuthorities/issuing"
            ),
            certificate_id="gateway-server",
            lifetime_days=90,
        )

    assert transport.gets == 0


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        ("wrong-key", "generated private key"),
        ("wrong-san", "SAN"),
        ("future", "not yet valid"),
        ("short-lifetime", "validity does not match"),
        ("ca-leaf", "must not be a CA"),
        ("missing-chain", "missing its issuer chain"),
        ("wrong-chain-signature", "signature is invalid"),
        ("missing-name", "unexpected certificate resource"),
        ("empty-name", "unexpected certificate resource"),
        ("wrong-name", "unexpected certificate resource"),
        ("wrong-issuer-resource", "unexpected issuing certificate authority"),
    ],
)
def test_enterprise_ca_issuance_rejects_untrusted_returned_leaf_or_chain(
    tamper: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        CertificateIssuer(FakePrivateCaTransport(tamper=tamper)).issue_enterprise_ca(
            hostname="demo.internal",
            ca_pool="projects/p/locations/asia-east1/caPools/enterprise",
            ca_name=(
                "projects/p/locations/asia-east1/caPools/enterprise/"
                "certificateAuthorities/issuing"
            ),
            certificate_id="gateway-server",
            lifetime_days=90,
        )


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


def test_secret_contract_allows_omitted_public_root() -> None:
    bundle = CertificateIssuer().issue_local_poc(
        hostname="demo-server-http.internal",
        lifetime_days=30,
    )
    document = json.loads(bundle.secret_payload())
    document["certificate_chain_pem"] = []

    fingerprint, _ = CertificateIssuer.validate_secret_payload(
        json.dumps(document).encode(),
        hostname="demo-server-http.internal",
        minimum_validity_days=1,
    )

    assert fingerprint == bundle.fingerprint_sha256


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


def test_secret_contract_rejects_mismatched_private_key() -> None:
    bundle = CertificateIssuer().issue_local_poc(
        hostname="demo-server-http.internal",
        lifetime_days=30,
    )
    other = CertificateIssuer().issue_local_poc(
        hostname="demo-server-http.internal",
        lifetime_days=30,
    )
    document = json.loads(bundle.secret_payload())
    document["private_key_pem"] = other.private_key_pem.decode("ascii")

    with pytest.raises(ValueError, match="do not match"):
        CertificateIssuer.validate_secret_payload(
            json.dumps(document).encode(),
            hostname="demo-server-http.internal",
            minimum_validity_days=1,
        )


def test_secret_contract_rejects_unrelated_issuer_chain() -> None:
    bundle = CertificateIssuer().issue_local_poc(
        hostname="demo-server-http.internal",
        lifetime_days=30,
    )
    other = CertificateIssuer().issue_local_poc(
        hostname="demo-server-http.internal",
        lifetime_days=30,
    )
    document = json.loads(bundle.secret_payload())
    document["certificate_chain_pem"] = [
        other.certificate_chain_pem[0].decode("ascii")
    ]

    with pytest.raises(ValueError, match=r"signature|leaf-to-root"):
        CertificateIssuer.validate_secret_payload(
            json.dumps(document).encode(),
            hostname="demo-server-http.internal",
            minimum_validity_days=1,
        )


def test_secret_contract_rejects_not_yet_valid_leaf() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Future Root")])
    now = datetime.now(UTC)
    issuer = (
        x509.CertificateBuilder()
        .subject_name(issuer_name)
        .issuer_name(issuer_name)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo.internal")]))
        .issuer_name(issuer_name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(hours=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("demo.internal")]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )
    payload = json.dumps(
        {
            "certificate_pem": leaf.public_bytes(serialization.Encoding.PEM).decode(),
            "certificate_chain_pem": [
                issuer.public_bytes(serialization.Encoding.PEM).decode()
            ],
            "private_key_pem": private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
        }
    ).encode()

    with pytest.raises(ValueError, match="not yet valid"):
        CertificateIssuer.validate_secret_payload(
            payload,
            hostname="demo.internal",
            minimum_validity_days=1,
        )
