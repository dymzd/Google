"""Emit the planner's API and permission constants as a TypeScript module.

Run from the repository root:

    python secure-gateway-studio/backend/tests/fixtures/planner/emit_constants.py

The permission set is 111 entries and the API sets are another 29. Transcribing
them by hand would be a slow, silent source of drift: a single mistyped
permission produces a deployer role that is wrong in exactly one way, and the
symptom appears as a denied API call during Apply rather than as a test
failure.

Generating them keeps one definition. CI regenerates and fails on any diff, so
the checked-in file cannot fall behind `domain/planner.py`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_BACKEND_SRC = Path(__file__).resolve().parents[3] / "src"
sys.path.insert(0, str(_BACKEND_SRC))

from sgstudio.domain.planner import (  # noqa: E402
    DIRECT_HTTPS_APIS,
    REQUIRED_APIS,
    REQUIRED_PERMISSIONS,
)

_ROLE_MANIFEST = (
    Path(__file__).resolve().parents[4]
    / "infrastructure"
    / "iam"
    / "secure-gateway-poc-deployer-role.yaml"
)


def _bootstrap_role() -> dict[str, object]:
    """The compatibility-named bootstrap role, as the IAM API expects it.

    The extension creates this role over REST instead of handing a YAML file to
    `gcloud`, so the manifest has to travel with the extension. Generating it
    keeps one definition: the all-path manifest the Python implementation
    uploads is the same role the extension uploads. The filename and exported
    constant retain "poc" only because existing deployments use that role ID.
    """
    text = _ROLE_MANIFEST.read_text(encoding="utf-8")
    permissions = [
        line.removeprefix("  - ").strip()
        for line in text.splitlines()
        if line.startswith("  - ")
    ]
    fields: dict[str, object] = {"includedPermissions": sorted(permissions)}
    for key in ("title", "description", "stage"):
        for line in text.splitlines():
            if line.startswith(f"{key}:"):
                fields[key] = line.split(":", 1)[1].strip()
                break
    return fields

_TARGET = (
    Path(__file__).resolve().parents[4] / "extension" / "src" / "domain" / "constants.generated.ts"
)

_HEADER = """/**
 * Generated from `backend/src/sgstudio/domain/planner.py`. Do not edit.
 *
 * Regenerate with:
 *   python backend/tests/fixtures/planner/emit_constants.py
 *
 * CI regenerates this file and fails on any diff, so it cannot fall behind the
 * Python definition. A hand-edited permission here would produce a deployer
 * role wrong in exactly one way, surfacing as a denied API call during Apply
 * rather than as a test failure.
 */
"""


def _emit(name: str, values: set[str]) -> str:
    entries = "\n".join(f'  "{value}",' for value in sorted(values))
    return f"export const {name}: readonly string[] = [\n{entries}\n];\n"


def main() -> None:
    body = "\n".join(
        [
            _HEADER,
            _emit("REQUIRED_APIS", set(REQUIRED_APIS)),
            _emit("DIRECT_HTTPS_APIS", set(DIRECT_HTTPS_APIS)),
            _emit("REQUIRED_PERMISSIONS", set(REQUIRED_PERMISSIONS)),
            "export const POC_DEPLOYER_ROLE = "
            + json.dumps(_bootstrap_role(), indent=2, sort_keys=True)
            + " as const;\n",
        ]
    )
    _TARGET.write_text(body, encoding="utf-8")
    print(
        f"wrote {len(REQUIRED_APIS)} APIs, {len(DIRECT_HTTPS_APIS)} direct-HTTPS APIs, "
        f"and {len(REQUIRED_PERMISSIONS)} permissions to {_TARGET.name}"
    )


if __name__ == "__main__":
    main()
