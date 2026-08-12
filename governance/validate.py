"""Validate the agent security manifest three ways:

1. Schema      - the manifest is well-formed (schema/agent-manifest.schema.json).
2. Policy      - the governance invariants hold (model has no authority, approvals fail
                 closed, side-effecting tools are approval-gated and request-only, runtime
                 is offline, MCP integrity controls are on).
3. Implementation - every control the manifest claims (`enforced_by` / `emitted_by`) actually
                 exists as a function in ../engineering-core. This is what stops the manifest
                 from drifting into fiction: governance is checked against the code.

Usage:  python validate.py          # runs all three, prints a summary, exits non-zero on failure
Requires: pyyaml, jsonschema  (pip install pyyaml jsonschema)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "agent-security-manifest.yaml"
SCHEMA = ROOT / "schema" / "agent-manifest.schema.json"
IMPL_SRC = ROOT.parent / "engineering-core" / "src" / "soc_triage_agent"


def load_manifest() -> dict:
    return yaml.safe_load(MANIFEST.read_text())


def check_schema(m: dict) -> list[tuple[bool, str]]:
    validator = Draft202012Validator(json.loads(SCHEMA.read_text()))
    errors = sorted(validator.iter_errors(m), key=lambda e: list(e.path))
    if errors:
        return [
            (False, f"schema: {'/'.join(map(str, e.path)) or '<root>'}: {e.message}")
            for e in errors[:6]
        ]
    return [(True, "schema: manifest conforms to agent-manifest.schema.json")]


def check_policy(m: dict) -> list[tuple[bool, str]]:
    out: list[tuple[bool, str]] = []

    def chk(ok: bool, msg: str) -> None:
        out.append((ok, msg))

    chk(
        m["model"]["authority"] == "none",
        "model has no authority to act (model proposes only)",
    )
    chk(
        m["model"]["key_source"] == "environment_only",
        "model keys sourced from environment only",
    )
    chk(
        m["approvals"]["on_timeout"] == "deny"
        and m["approvals"]["fail_closed"] is True,
        "approvals fail closed on timeout",
    )
    chk(m["network"]["runtime"] == "none", "no runtime network egress")
    chk(
        m["limits"]["containment_execution"] == "none",
        "containment is request-only; no real action path",
    )
    chk(
        all(
            m["mcp_integrity"][k] is True
            for k in ("tool_allowlist", "schema_pinning", "drift_detection")
        ),
        "MCP integrity: allowlist + schema pinning + drift detection all enabled",
    )
    chk(
        len(m["evaluation"]["required_suites"]) >= 3,
        "at least 3 evaluation suites are required",
    )

    side_effecting = [t for t in m["tools"] if t.get("side_effects")]
    bad = [
        t["name"]
        for t in side_effecting
        if not (t.get("approval_required") and t.get("request_only"))
    ]
    chk(
        not bad,
        "every side-effecting tool is approval-gated and request-only"
        + (f" (violations: {bad})" if bad else ""),
    )
    for t in side_effecting:
        chk(
            t.get("allowed_only_when_verdict") == "likely-compromise",
            f"{t['name']} is gated to a likely-compromise verdict",
        )
    read_only = [t["name"] for t in m["tools"] if not t.get("side_effects")]
    chk(
        len(read_only) >= 1,
        f"read-only enrichment tools declared: {', '.join(read_only)}",
    )
    return out


def _referenced_controls(node) -> set[tuple[str, str]]:
    """Collect (module, function) pairs from every enforced_by/emitted_by string."""
    found: set[tuple[str, str]] = set()

    def walk(value, key=None):
        if isinstance(value, dict):
            for k, v in value.items():
                walk(v, k)
        elif isinstance(value, list):
            for item in value:
                walk(item, key)
        elif isinstance(value, str) and key in {"enforced_by", "emitted_by"}:
            for mod, fn in re.findall(r"\b([a-z_]+)\.([a-z_]+)\b", value):
                found.add((mod, fn))

    walk(node)
    return found


def check_implementation(m: dict) -> list[tuple[bool, str]]:
    out: list[tuple[bool, str]] = []
    if not IMPL_SRC.is_dir():
        return [
            (
                False,
                f"implementation not found at {IMPL_SRC} (run from the repo with engineering-core/ present)",
            )
        ]
    sources = {p.stem: p.read_text() for p in IMPL_SRC.glob("*.py")}
    for module, fn in sorted(_referenced_controls(m)):
        text = sources.get(module, "")
        present = bool(re.search(rf"\bdef\s+{re.escape(fn)}\b", text))
        out.append(
            (
                present,
                f"control implemented: {module}.{fn}()"
                + ("" if present else " — NOT FOUND in engineering-core"),
            )
        )
    suites_file = IMPL_SRC.parent.parent / "tests" / "test_guardrails.py"
    tests_text = suites_file.read_text() if suites_file.is_file() else ""
    for suite in m["evaluation"]["required_suites"]:
        present = f"def {suite}" in tests_text
        out.append(
            (
                present,
                f"eval suite present: {suite}" + ("" if present else " — NOT FOUND"),
            )
        )
    return out


def main() -> int:
    m = load_manifest()
    sections = [
        ("SCHEMA", check_schema(m)),
        ("POLICY", check_policy(m)),
        ("IMPLEMENTATION", check_implementation(m)),
    ]
    total = passed = 0
    for title, results in sections:
        print(f"\n[{title}]")
        for ok, msg in results:
            total += 1
            passed += ok
            print(f"  {'PASS' if ok else 'FAIL'}  {msg}")
    print(f"\n=== {passed}/{total} checks passed ===")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
