"""Package dist/ for the Web Store.

Timestamps are fixed. A ZIP that records build time is not byte-reproducible,
which would defeat the point of publishing the source: a customer could not
confirm that the uploaded artefact came from this commit.
"""

import hashlib
import zipfile
from pathlib import Path

DIST = Path(__file__).parent / "dist"
TARGET = Path(__file__).parent / "dist.zip"


def main() -> None:
    files = sorted(p for p in DIST.rglob("*") if p.is_file() and p.name != "SHA256SUMS.json")
    with zipfile.ZipFile(TARGET, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            info = zipfile.ZipInfo(
                str(path.relative_to(DIST)).replace("\\", "/"),
                date_time=(1980, 1, 1, 0, 0, 0),
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())
    digest = hashlib.sha256(TARGET.read_bytes()).hexdigest()
    print(f"{TARGET.name}  {TARGET.stat().st_size} bytes")
    print(f"sha256  {digest}")


if __name__ == "__main__":
    main()
