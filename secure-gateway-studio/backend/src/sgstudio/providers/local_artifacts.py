from __future__ import annotations

import os
from pathlib import Path


class CertificateArtifactStore:
    """Stores only public CA certificates produced by a local PoC run."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()

    def _path(self, deployment_name: str) -> Path:
        if not deployment_name or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
            for character in deployment_name
        ):
            raise ValueError("Invalid deployment name for certificate artifact")
        return self._root / f"{deployment_name}-poc-root.pem"

    def write_root_certificate(self, deployment_name: str, certificate: bytes) -> Path:
        if not certificate.startswith(b"-----BEGIN CERTIFICATE-----\n"):
            raise ValueError("Certificate artifact must contain one PEM certificate")
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self._path(deployment_name)
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(certificate)
        os.chmod(temporary, 0o600)
        temporary.replace(path)
        return path

    def read_root_certificate(self, deployment_name: str) -> bytes:
        return self._path(deployment_name).read_bytes()

    def remove_root_certificate(self, deployment_name: str) -> None:
        self._path(deployment_name).unlink(missing_ok=True)
