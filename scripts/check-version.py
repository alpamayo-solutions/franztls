#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 CI compatibility.
    from setuptools._vendor import tomli as tomllib


EXPECTED_MODULE = "github.com/alpamayo-solutions/franztls"
TAG_PATTERN = re.compile(r"v([0-9]+\.[0-9]+\.[0-9]+)")


def fail(message: str) -> None:
    raise SystemExit(message)


def python_version(root: Path) -> str:
    try:
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))[
            "project"
        ]
        version = project["version"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError):
        fail("unable to read the Python package version")
    if not isinstance(version, str) or not version:
        fail("Python package version must be a nonempty string")
    return version


def verify_go_module(root: Path) -> None:
    try:
        lines = (root / "go.mod").read_text(encoding="utf-8").splitlines()
    except OSError:
        fail("unable to read go.mod")

    module_names: list[str] = []
    for raw_line in lines:
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("module "):
            module_names.append(line.removeprefix("module ").strip())
        if re.match(r"^replace(?:\s|\()", line):
            fail("go.mod must not contain a replace directive")

    if module_names != [EXPECTED_MODULE]:
        fail("go.mod must declare the canonical franztls module")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        fail("usage: check-version.py vX.Y.Z")

    tag = argv[1]
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        fail("release tag must be vX.Y.Z")

    root = Path.cwd()
    package_version = python_version(root)
    if match.group(1) != package_version:
        fail(f"tag {tag} does not match Python version {package_version}")

    verify_go_module(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
