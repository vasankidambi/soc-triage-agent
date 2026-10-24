#!/usr/bin/env python3
"""Mutation check: apply 21 hand-written faults to the guardrail code, one at a
time, and report which ones the test suite catches. A mutant is "killed" when
pytest exits non-zero.

The mutants are applied in a throwaway git worktree of HEAD, never in the real
checkout, which is required to be clean before and after. The worktree gets its
own interpreter because the MCP tool server runs as a subprocess with a reduced
environment (no PYTHONPATH), so only a venv that puts the worktree package first
on sys.path mutates the server as well as the client.

Usage, from the repository root inside the project venv:
    python scripts/mutation_check.py [--suite all|repo|attacks] [--only M01,M07] [--json out.json]
Exit code 2 means the check itself could not run, not that a mutant survived.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import site
import subprocess  # nosec B404
import sys
import sysconfig
import tempfile
from pathlib import Path
from typing import NamedTuple

# Every subprocess call below uses a fixed argv and no shell (bandit B404/B603).

REPO_ROOT = Path(__file__).resolve().parents[1]
GIT = shutil.which("git") or "git"
SRC_REL = Path("engineering-core") / "src" / "soc_triage_agent"

# Imports the test dependencies and prints where the package comes from.
PROBE = (
    "import pathlib, pytest, langgraph, mcp, soc_triage_agent;"
    " print(pathlib.Path(soc_triage_agent.__file__).resolve().parent)"
)

SUITES = {
    "all": ["tests"],
    "repo": ["tests/test_guardrails.py"],
    "attacks": ["tests/test_attacks.py"],
}


class Mutant(NamedTuple):
    id: str
    description: str
    file: str
    old: str
    new: str


MUTANTS = [
    Mutant(
        "M01",
        "tool calls allowed when triage unauthorized",
        "guardrails.py",
        '    if not triage_authorized:\n        raise PolicyDenied("tool call denied: triage is not authorized")\n',
        "",
    ),
    Mutant(
        "M02",
        "containment allowed for any verdict",
        "guardrails.py",
        "if tool_name == CONTAINMENT_TOOL and verdict == VerdictLabel.LIKELY_COMPROMISE:",
        "if tool_name == CONTAINMENT_TOOL:",
    ),
    Mutant(
        "M03",
        "expired deadline ignored",
        "guardrails.py",
        'if response.decision == "timeout" or current >= expiry:',
        'if response.decision == "timeout":',
    ),
    Mutant(
        "M04",
        "reject treated as approve",
        "guardrails.py",
        '"status": "rejected",',
        '"status": "approved",',
    ),
    Mutant(
        "M05",
        "verdict accepts extra fields",
        "guardrails.py",
        'class Verdict(BaseModel):\n    model_config = ConfigDict(extra="forbid")',
        'class Verdict(BaseModel):\n    model_config = ConfigDict(extra="ignore")',
    ),
    Mutant(
        "M06",
        "plan may include write tools",
        "guardrails.py",
        '        if unknown:\n            raise ValueError(\n                f"investigation plan requested',
        '        if False:\n            raise ValueError(\n                f"investigation plan requested',
    ),
    Mutant(
        "M07",
        "schema comparison skipped",
        "mcp_client.py",
        "        if actual != pinned:",
        "        if False:",
    ),
    Mutant(
        "M08",
        "bool type check removed",
        "mcp_client.py",
        '        if expected_type == "boolean" and type(value) is not bool:',
        "        if False:",
    ),
    Mutant(
        "M09",
        "nesting depth limit raised",
        "guardrails.py",
        "if depth > 8:",
        "if depth > 800:",
    ),
    Mutant(
        "M10",
        "tenant not checked",
        "guardrails.py",
        '        "tenant_id": "tenant-soc-lab",\n',
        "",
    ),
    Mutant(
        "M11",
        "real IPs accepted",
        "guardrails.py",
        "        if not any(address in network for network in documentation_ranges):",
        "        if False:",
    ),
    Mutant(
        "M12",
        "actioned even when not approved",
        "graph.py",
        '        recommendation["actioned"] = False\n        recommendation["action_status"] = "not-actioned"',
        '        recommendation["actioned"] = True\n        recommendation["action_status"] = "not-actioned"',
    ),
    Mutant(
        "M13",
        "human approval skipped",
        "graph.py",
        'return "human_approval" if state.get("containment_required") else "report"',
        'return "report"',
    ),
    Mutant(
        "M14",
        "server-side containment check removed",
        "mcp_server.py",
        '    if not authorized or not approval_required or verdict != "likely-compromise":\n        raise ValueError',
        "    if False:\n        raise ValueError",
    ),
    Mutant(
        "M15",
        "edited actions not policy-checked",
        "guardrails.py",
        '        if unknown:\n            raise ValueError(f"edited actions are outside policy',
        '        if False:\n            raise ValueError(f"edited actions are outside policy',
    ),
    Mutant(
        "M16",
        "unknown-tool check removed in broker",
        "mcp_client.py",
        '        if tool_name not in PINNED_INPUT_SCHEMAS:\n            raise PolicyDenied(f"unknown MCP tool denied: {tool_name}")\n',
        "",
    ),
    Mutant(
        "M17",
        "inventory drift check removed",
        "mcp_client.py",
        "    if unknown or missing:",
        "    if False:",
    ),
    Mutant(
        "M18",
        "const verdict check removed",
        "mcp_client.py",
        '        if "const" in rule and value != rule["const"]:',
        "        if False:",
    ),
    Mutant(
        "M19",
        "finite and range check removed from the reputation score",
        "model_adapter.py",
        "    risk_score: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)",
        "    risk_score: float",
    ),
    Mutant(
        "M20",
        "bool accepted as a number (strict parsing off)",
        "model_adapter.py",
        '    model_config = ConfigDict(extra="ignore", strict=True)',
        '    model_config = ConfigDict(extra="ignore", strict=False)',
    ),
    Mutant(
        "M21",
        "timestamps compared as text",
        "model_adapter.py",
        "    return max(parsed, key=lambda event: event.instant)",
        "    return max(parsed, key=lambda event: event.observed_at)",
    ),
]


def _fail(message: str) -> None:
    print(f"mutation_check: {message}", file=sys.stderr)
    sys.exit(2)


def _git(*args: str) -> str:
    result = subprocess.run(  # nosec B603
        [GIT, "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        _fail(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _assert_real_tree_clean(moment: str) -> None:
    status = _git("status", "--porcelain", "--", str(SRC_REL)).strip()
    if status:
        _fail(f"source tree is not clean {moment} the run:\n{status}")


def _make_worktree(tmp: Path) -> Path:
    worktree = tmp / "worktree"
    _git("worktree", "add", "--detach", str(worktree), "HEAD")
    return worktree


def _remove_worktree(worktree: Path) -> None:
    for args in (
        ("worktree", "remove", "--force", str(worktree)),
        ("worktree", "prune"),
    ):
        subprocess.run(  # nosec B603
            [GIT, "-C", str(REPO_ROOT), *args],
            capture_output=True,
            text=True,
            check=False,
        )


def _make_venv(tmp: Path, worktree: Path) -> Path:
    """Create an interpreter that imports soc_triage_agent from the worktree copy."""
    venv = tmp / "venv"
    subprocess.run(  # nosec B603
        [sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True
    )
    if os.name == "nt":
        python = venv / "Scripts" / "python.exe"
        site_dir = venv / "Lib" / "site-packages"
    else:
        python = venv / "bin" / "python"
        version = f"python{sys.version_info.major}.{sys.version_info.minor}"
        site_dir = venv / "lib" / version / "site-packages"
    site_dir.mkdir(parents=True, exist_ok=True)
    outer: list[str] = []
    for entry in [sysconfig.get_paths()["purelib"], *site.getsitepackages()]:
        if entry not in outer and Path(entry).is_dir():
            outer.append(entry)
    # .pth entries are appended to sys.path in file-name order: the worktree source
    # first, then the outer environment's packages (pytest, langgraph, mcp, ...).
    (site_dir / "000-worktree-src.pth").write_text(
        f"{(worktree / SRC_REL).parent.resolve()}\n", encoding="utf-8"
    )
    (site_dir / "zzz-outer-site-packages.pth").write_text(
        "\n".join(outer) + "\n", encoding="utf-8"
    )
    expected = (worktree / SRC_REL).resolve()
    probe = subprocess.run(  # nosec B603
        [
            str(python),
            "-c",
            PROBE,
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp,
    )
    if probe.returncode != 0:
        _fail(
            "worktree venv cannot import the project or its test dependencies; "
            f"run this from the project venv:\n{probe.stderr}"
        )
    if Path(probe.stdout.strip()) != expected:
        _fail(
            f"worktree venv imports soc_triage_agent from {probe.stdout.strip()}, "
            f"expected {expected}"
        )
    return python


def _suite_fails(python: Path, worktree: Path, targets: list[str]) -> bool:
    result = subprocess.run(  # nosec B603
        [
            str(python),
            "-m",
            "pytest",
            "-q",
            "-x",
            "-p",
            "no:cacheprovider",
            "-o",
            "addopts=",
            *targets,
        ],
        cwd=worktree / "engineering-core",
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    return result.returncode != 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--suite", choices=sorted(SUITES), default="all")
    parser.add_argument(
        "--only", help="comma-separated mutant ids, for example M01,M07"
    )
    parser.add_argument("--json", type=Path, help="write the results to this JSON file")
    args = parser.parse_args()

    targets = SUITES[args.suite]
    for target in targets:
        if not (REPO_ROOT / "engineering-core" / target).exists():
            _fail(f"test target not found: {target}")
    selected = MUTANTS
    if args.only:
        wanted = {item.strip() for item in args.only.split(",")}
        selected = [m for m in MUTANTS if m.id in wanted]
    if shutil.which("git") is None:
        _fail("git is required")

    _assert_real_tree_clean("before")
    _git("worktree", "prune")  # leftovers from a run that was killed mid-flight
    tmp = Path(tempfile.mkdtemp(prefix="soc-triage-mutants-"))
    worktree: Path | None = None
    results: list[dict[str, object]] = []
    try:
        worktree = _make_worktree(tmp)
        python = _make_venv(tmp, worktree)
        if _suite_fails(python, worktree, targets):
            _fail(
                "the unmutated suite does not pass; fix that before measuring mutants"
            )
        for mutant in selected:
            path = worktree / SRC_REL / mutant.file
            original = path.read_text(encoding="utf-8")
            if original.count(mutant.old) != 1:
                _fail(
                    f"{mutant.id}: expected exactly one match in {mutant.file}, "
                    f"found {original.count(mutant.old)}; update the mutant"
                )
            path.write_text(original.replace(mutant.old, mutant.new), encoding="utf-8")
            try:
                killed = _suite_fails(python, worktree, targets)
            finally:
                path.write_text(original, encoding="utf-8")
            results.append(
                {
                    "id": mutant.id,
                    "description": mutant.description,
                    "file": mutant.file,
                    "killed": killed,
                }
            )
            print(
                f"{mutant.id} {'KILLED  ' if killed else 'SURVIVED'} {mutant.description}",
                flush=True,
            )
    finally:
        if worktree is not None:
            _remove_worktree(worktree)
        shutil.rmtree(tmp, ignore_errors=True)
        _assert_real_tree_clean("after")

    killed_total = sum(1 for r in results if r["killed"])
    print(f"SCORE suite={args.suite}: {killed_total}/{len(results)} mutants killed")
    if args.json:
        summary = {
            "suite": args.suite,
            "targets": targets,
            "head": _git("rev-parse", "HEAD").strip(),
            "killed": killed_total,
            "total": len(results),
            "results": results,
        }
        args.json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
