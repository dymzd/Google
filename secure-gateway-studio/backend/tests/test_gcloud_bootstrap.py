from subprocess import CompletedProcess

import pytest

from sgstudio.providers.gcloud_bootstrap import GcloudDeployerBootstrapper


def test_noninteractive_reauthentication_failure_has_actionable_remediation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(gcloud_path="/usr/bin/false")

    def failed_run(*args, **kwargs):
        del args, kwargs
        return CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr=(
                "Reauthentication failed. cannot prompt during non-interactive "
                "execution."
            ),
        )

    monkeypatch.setattr("sgstudio.providers.gcloud_bootstrap.subprocess.run", failed_run)

    with pytest.raises(RuntimeError, match="gcloud auth login"):
        bootstrapper._run("iam", "roles", "describe", "example")
