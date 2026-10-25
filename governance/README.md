# Governance

The security-architect layer for the SOC triage agent. Where [`../engineering-core`](../engineering-core)
*builds* the agent and enforces controls inline, this folder *governs* it: it declares the agent's security
contract, maps every control to industry frameworks, models the threats, and, the part that matters,
**checks the governance against the actual code** so drift between them is caught.

A manifest that claims controls the code doesn't implement is theater. Here the manifest names the
enforcement functions and tests behind its controls, and `validate.py` fails if any of those named
functions or tests is missing.

This is a lightweight **governance-as-code / control-consistency** layer, inspired by the NIST OSCAL
pattern (a machine-readable control register mapped to implementation, with an automated check). It
verifies the governance stays *consistent* with the code (the invariants are declared and the named
functions and tests exist), not that the controls are behaviorally proven (the `test_guardrails.py`
suite exercises those behaviors), nor that the code "meets" a framework (the mappings are a curated crosswalk).

## Contents

| File | What it is |
|---|---|
| `agent-security-manifest.yaml` | The agent's declared, machine-readable security contract: scope, model authority, tools, approvals, network, logging, limits, MCP integrity, required evals. Key controls cite the enforcement function or emitter behind them. |
| `schema/agent-manifest.schema.json` | JSON Schema the manifest must satisfy. |
| `validate.py` | Validates the manifest three ways: schema, governance policy invariants, and **implementation cross-check** (every enforcement function and guardrail test the manifest names exists in `../engineering-core`). |
| `control-matrix.md` | Each implemented control mapped to OWASP LLM Top 10 (2025), MITRE ATLAS, and NIST AI RMF, with code citations. |
| `threat-model.md` | Threat model of the implemented system: misuse cases → defending control → the code or test that supports it. |

## Run the governance check

```bash
cd governance
python3 -m pip install pyyaml jsonschema
python3 validate.py
```

Expected: `24/24 checks passed`: 1 schema check, 10 policy-invariant checks (the manifest declares the
intended rules), and 13 implementation checks: the 7 enforcement functions and 6 guardrail tests the
manifest names all exist in `../engineering-core`.

## The principle

> The model proposes; deterministic policy authorizes; MCP executes; a human approves anything
> consequential, and the audit trail and evals make that claim checkable, not just stated.

This layer is how a security architect governs an agent they built: the contract is explicit, mapped to
the frameworks auditors ask about (NIST AI RMF, OWASP, MITRE ATLAS), and continuously verifiable against
the implementation.
