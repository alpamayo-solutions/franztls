from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VERSION_GUARD = REPOSITORY_ROOT / "scripts" / "check-version.py"
SECRET_ENVIRONMENT_VALUES = {
    "FRANZTLS_GUARD_SECRET": "task14-environment-secret",
    "GITHUB_TOKEN": "task14-fake-github-token",
}


def run_guard(tag: str, cwd: Path = REPOSITORY_ROOT) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(SECRET_ENVIRONMENT_VALUES)
    return subprocess.run(
        [sys.executable, str(VERSION_GUARD), tag],
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )


@pytest.mark.parametrize(
    ("tag", "expected_code"),
    [
        ("v0.2.0", 0),
        ("v0.2.1", 1),
        ("0.2.0", 1),
        ("v0.2.0b1", 1),
        ("release-v0.2.0", 1),
    ],
)
def test_release_tag_must_match_the_exact_python_version(
    tag: str,
    expected_code: int,
) -> None:
    result = run_guard(tag)

    assert result.returncode == expected_code
    assert result.stdout == ""
    if expected_code == 0:
        assert result.stderr == ""
    for secret in SECRET_ENVIRONMENT_VALUES.values():
        assert secret not in result.stdout
        assert secret not in result.stderr


@pytest.mark.parametrize(
    "go_mod",
    [
        "module example.com/wrong\n\ngo 1.25.12\n",
        (
            "module github.com/alpamayo-solutions/franztls\n\n"
            "go 1.25.12\n\n"
            "replace github.com/example/dependency => ../dependency\n"
        ),
    ],
)
def test_release_guard_rejects_wrong_module_or_replace(
    tmp_path: Path,
    go_mod: str,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "franztls"\nversion = "0.2.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "go.mod").write_text(go_mod, encoding="utf-8")

    result = run_guard("v0.2.0", cwd=tmp_path)

    assert result.returncode == 1
    assert result.stdout == ""
    for secret in SECRET_ENVIRONMENT_VALUES.values():
        assert secret not in result.stderr
