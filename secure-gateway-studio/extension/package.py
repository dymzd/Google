"""Package dist/ for the Web Store.

Timestamps are fixed and entries are stored without DEFLATE. Besides making the
archive easier to inspect, avoiding zlib-version-dependent compressed bytes is
required for byte-for-byte reproducibility across build hosts.
"""

import hashlib
import json
import zipfile
from pathlib import Path

DIST = Path(__file__).parent / "dist"
MANIFEST = Path(__file__).parent / "manifest.json"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ZIP_CREATE_SYSTEM = 3  # Unix, fixed on Windows and Linux alike.
ZIP_FILE_MODE = 0o100644


def main() -> None:
    source_manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    dist_manifest_path = DIST / "manifest.json"
    dist_manifest = json.loads(dist_manifest_path.read_text(encoding="utf-8"))
    if dist_manifest != source_manifest:
        raise RuntimeError("dist/manifest.json is stale; run the build again before packaging")
    version = dist_manifest.get("version")
    version_parts = version.split(".") if isinstance(version, str) else []
    if (
        not 1 <= len(version_parts) <= 4
        or any(not part.isdigit() or int(part) > 65535 for part in version_parts)
    ):
        raise RuntimeError("manifest.json has no safe numeric extension version")
    target = Path(__file__).parent / f"secure-gateway-studio-{version}.zip"
    # Include the build's per-file digest manifest in the uploaded archive. It
    # deliberately does not hash itself, but it lets reviewers compare every
    # executable/static payload without rebuilding the source first.
    # Path ordering is platform-specific (WindowsPath compares with Windows
    # semantics). Sort the normalized archive names explicitly so Windows and
    # POSIX builders emit the same central-directory order.
    files = sorted(
        (p for p in DIST.rglob("*") if p.is_file()),
        key=lambda path: path.relative_to(DIST).as_posix(),
    )
    manifest_path = DIST / "SHA256SUMS.json"
    recorded = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload = {
        path.relative_to(DIST).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in files
        if path != manifest_path
    }
    if recorded != payload:
        raise RuntimeError(
            "dist/SHA256SUMS.json does not exactly cover the package payload; "
            "run the build again before packaging"
        )
    with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as archive:
        for path in files:
            info = zipfile.ZipInfo(
                str(path.relative_to(DIST)).replace("\\", "/"),
                date_time=ZIP_TIMESTAMP,
            )
            # ZipInfo otherwise records the host Python's platform (0 on
            # Windows, 3 on Unix), changing central-directory bytes and the
            # archive digest even when every payload byte is identical.
            info.create_system = ZIP_CREATE_SYSTEM
            info.create_version = 20
            info.extract_version = 20
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = ZIP_FILE_MODE << 16
            archive.writestr(info, path.read_bytes())
    with zipfile.ZipFile(target, "r") as archive:
        entries = archive.infolist()
        expected_names = [path.relative_to(DIST).as_posix() for path in files]
        if expected_names != sorted(expected_names):
            raise RuntimeError("ZIP entry names are not in platform-neutral lexical order")
        if archive.comment != b"" or [entry.filename for entry in entries] != expected_names:
            raise RuntimeError("ZIP entry order or archive comment is not deterministic")
        for entry in entries:
            if (
                entry.create_system != ZIP_CREATE_SYSTEM
                or entry.create_version != 20
                or entry.extract_version != 20
                or entry.date_time != ZIP_TIMESTAMP
                or entry.compress_type != zipfile.ZIP_STORED
                or entry.external_attr != ZIP_FILE_MODE << 16
                or entry.extra != b""
                or entry.comment != b""
            ):
                raise RuntimeError(f"ZIP metadata is not deterministic for {entry.filename}")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    # 0.2.0 and earlier used the ambiguous dist.zip name. Remove that one exact
    # obsolete artefact only after the versioned archive has been written and
    # hashed successfully, so operators cannot accidentally upload the old ZIP.
    legacy_target = Path(__file__).parent / "dist.zip"
    legacy_target.unlink(missing_ok=True)
    print(f"{target.name}  {target.stat().st_size} bytes")
    print(f"sha256  {digest}")


if __name__ == "__main__":
    main()
