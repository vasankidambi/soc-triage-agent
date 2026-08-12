# Threat Model — SOC Triage Agent

Scope: the defensive SOC alert-triage agent in `../engineering-core`. Every misuse case names the
control that defends it and the code or test that supports the defense. This is a threat model of the
*implemented* system, not a generic checklist.

## Assets

A1 Integrity of the triage verdict · A2 The containment action path (must never fire without a human) ·
A3 Synthetic identity/evidence data · A4 The audit trail · A5 Model/tool credentials · A6 The agent's
authority envelope (what it is allowed to do at all).

## Actors

Legitimate SOC analyst · Malicious or crafted alert content · A compromised or drifted MCP tool ·
The model itself as a confused deputy (induced, not malicious) · An operator running the agent out of scope.

## Trust boundaries

TB1 Alert intake ↔ agent · TB2 Agent ↔ model (proposals out) · TB3 Policy decision ↔ tool execution ·
TB4 High-impact action ↔ human approval · TB5 Everything ↔ audit sink.

## Misuse cases

| # | Misuse case | Boundary | Defending control | Evidence (code / test) |
|---|---|---|---|---|
| M1 | Prompt injection embedded in alert text or enrichment data induces an unauthorized action | TB2/TB3 | C5 input bounding + C6 injection-resistant prompt + **C3 deterministic mediation** (authority never leaves policy) | authorization tests; `authorize_tool_call` |
| M2 | Model "decides" to run a write/containment tool directly | TB3 | C3 complete mediation; containment gated to a likely-compromise verdict, not model choice | `test_unknown_mcp_tool_is_denied`; `authorize_tool_call` |
| M3 | Containment executes without human sign-off | TB4 | C8 human approval via `interrupt()`; C9 request-only tool | `test_containment_is_not_actioned_when_rejected`; `test_human_approval_marks_recommendation_actioned` |
| M4 | Approval is skipped by letting it time out (default-allow) | TB4 | C8 fail-closed: timeout and malformed responses deny | `test_approval_timeout_fails_closed` |
| M5 | A poisoned or swapped MCP tool changes its schema or a new tool appears | TB3 | C4 allow-list + schema pinning + drift detection | `test_unknown_mcp_tool_is_denied`; `validate_discovered_tools` |
| M6 | Out-of-scope alert (wrong tenant/queue/classification) is triaged | TB1 | C1 scope authorization; blocked before any tool runs | `test_unauthorized_triage_is_blocked_before_tools` |
| M7 | Real routable IPs leak into the system via a crafted alert (free-text `summary` is length-bounded, not PII-scanned) | TB1 | C2 strict schema + RFC 5737 documentation-IP enforcement | `validate_alert`; `Alert.validate_documentation_ip` |
| M8 | Malformed model output corrupts the verdict or report | TB2 | C7 strict Pydantic output validation (`extra="forbid"`) | schema validation in `plan/correlate/verdict` nodes |
| M9 | Credentials leak via code or config | TB5/A5 | C10 env-only keys; no secrets in repo; `detect-secrets` clean | secret scan reported clean; `model_adapter` |
| M10 | Agent loops or escalates through many actions | TB3 | C12 one containment/run; read-only fan-out cannot escalate | `risk_gate_node`; manifest `limits` |
| M11 | Actions taken without a record (repudiation) | TB5 | C11 audit event on every node decision, successful tool call, and approval (denied calls fail closed before a node event) | `graph._event`; `audit_event_count` in report |

## Assumptions and residual risk

The design assumes platform controls exist beneath it (host, network, SDLC). It deliberately does **not**
claim to prevent prompt injection at the model boundary — M1's containment is that injection may succeed at
TB2, so all authority is held in deterministic layers (TB3–TB4). Static validation checks the *contract* stays consistent with the code;
the `test_guardrails.py` suite exercises the *runtime* behavior. The stub model makes Phase 1 fully
deterministic; the same trust boundaries apply when a real model adapter is enabled, because the model's
role — propose only — does not change.
