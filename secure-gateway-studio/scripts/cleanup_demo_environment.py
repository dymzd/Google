#!/usr/bin/env python3
"""Safely tear down one deployment recorded by Secure Gateway Studio.

The command is a dry run unless ``--execute`` is supplied. It never discovers
resources by a shared name, project-wide listing, or organizational-unit name;
the state database's active ownership records are the sole cleanup scope.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_SRC = PROJECT_ROOT / "backend" / "src"
if str(BACKEND_SRC) not in sys.path:
    sys.path.insert(0, str(BACKEND_SRC))

from sgstudio.domain.teardown import TeardownExecutor, build_teardown_plan  # noqa: E402
from sgstudio.providers.google_executor import create_google_resource_executor  # noqa: E402
from sgstudio.storage.repository import StateRepository  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Preview or execute an ownership-bounded Secure Gateway Studio teardown"
        )
    )
    parser.add_argument(
        "--state-db",
        type=Path,
        required=True,
        help="Path to the Secure Gateway Studio SQLite state database",
    )
    parser.add_argument(
        "--run-id",
        required=True,
        help="Deployment run whose active ownership records define the cleanup scope",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Perform the displayed teardown; without this flag the command is read-only",
    )
    parser.add_argument(
        "--confirm",
        default="",
        help="Exact plan-specific confirmation printed by the dry run",
    )
    parser.add_argument(
        "--actor",
        default="cleanup-cli",
        help="Audit actor recorded for an executed teardown",
    )
    return parser


def _print_plan(plan) -> None:
    print(f"Run: {plan.run_id}")
    print(f"Plan hash: {plan.plan_hash}")
    print("Owned resources selected for teardown:")
    for resource in plan.resources:
        print(f"  - {resource.resource_key} ({resource.teardown_action})")
    if plan.retained_resources:
        print("Shared or unowned resources retained:")
        for resource in plan.retained_resources:
            print(f"  - {resource.resource_key}")
    print(f"Confirmation: {plan.confirmation}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    state_db = args.state_db.expanduser().resolve()
    if not state_db.is_file():
        parser.error(f"State database does not exist: {state_db}")

    repository = StateRepository(state_db)
    try:
        plan = build_teardown_plan(repository, args.run_id)
    except ValueError as error:
        parser.error(str(error))

    _print_plan(plan)
    if not plan.can_destroy:
        print("No active owned resources are available for teardown.", file=sys.stderr)
        return 1
    if not args.execute:
        print("DRY RUN: no Google API mutations were attempted.")
        print("Re-run with --execute and the exact --confirm value shown above.")
        return 0
    if args.confirm != plan.confirmation:
        parser.error("--confirm does not match the current ownership-bound teardown plan")

    teardown = repository.create_teardown_run(
        source_run_id=plan.run_id,
        plan_hash=plan.plan_hash,
        resource_keys=[resource.resource_key for resource in plan.resources],
        actor=args.actor,
    )
    provider = create_google_resource_executor()
    completed = TeardownExecutor(provider, repository).execute(
        teardown,
        actor=args.actor,
    )
    if completed.status != "succeeded":
        print(
            "Teardown stopped before all owned resources were deleted; ownership was retained "
            "for the incomplete resource.",
            file=sys.stderr,
        )
        return 1
    print("Ownership-bounded teardown completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
