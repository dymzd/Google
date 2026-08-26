from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT_PATH = Path(__file__).parents[2] / "scripts" / "cleanup_demo_environment.py"


def load_cleanup_module():
    module_spec = importlib.util.spec_from_file_location(
        "cleanup_demo_environment",
        SCRIPT_PATH,
    )
    assert module_spec is not None and module_spec.loader is not None
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


def test_cleanup_cli_is_dry_run_by_default_and_has_no_shared_resource_defaults() -> None:
    module = load_cleanup_module()

    parser = module.build_parser()
    args = parser.parse_args(["--state-db", "state.db", "--run-id", "run-123"])

    assert args.execute is False
    assert args.state_db == Path("state.db")
    assert args.run_id == "run-123"
    assert not hasattr(args, "project")
    assert not hasattr(args, "customer")
    assert not hasattr(args, "target_ou_name")
