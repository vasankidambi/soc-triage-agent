# Control Matrix

Each control implemented in `../engineering-core` mapped to its framework lineage. Framework columns
use OWASP LLM Top 10 (2025 numbering), MITRE ATLAS, and NIST AI RMF. Every row cites its
implementation site; `validate.py` confirms the sites named in the manifest exist. The framework columns
are a curated crosswalk — `validate.py` does not verify conformance to them.

| # | Control | Implementation site | OWASP LLM 2025 | MITRE ATLAS (concept) | NIST AI RMF |
|---|---|---|---|---|---|
| C1 | **Scope authorization** — only the synthetic identity-security lab queue is triaged; everything else is blocked before any tool runs | `guardrails.authorize_triage`, `graph.intake_node` → `block_node` | LLM06 Excessive Agency | Tool misuse prevention | MANAGE 2.2; MAP 5.1 |
| C2 | **Alert validation + synthetic-data enforcement** — strict field formats; source IPs forced to RFC 5737 documentation ranges (real IPs cannot enter); free-text `summary` is length-bounded and sanitized, not PII-scanned | `guardrails.validate_alert`, `Alert.validate_documentation_ip` | LLM02 Sensitive Information Disclosure | Data provenance | MEASURE 2.7; MAP 2.3 |
| C3 | **Complete mediation of tool calls** — every tool call is authorized by deterministic policy independent of the model; containment is permitted only when the verdict is likely-compromise | `guardrails.authorize_tool_call`, `mcp_client.MCPToolBroker.call_tool` | LLM06 Excessive Agency | Unauthorized action | GOVERN 3.2; MANAGE 2.2 |
| C4 | **MCP integrity** — client allow-lists tools, pins input schemas, and rejects inventory or schema drift | `mcp_client.validate_discovered_tools`, `_validate_arguments` | LLM03 Supply Chain; LLM04 Model/Data Poisoning | Tool poisoning; ML supply chain compromise | GOVERN 6.1; MAP 4.1 |
| C5 | **Untrusted-input bounding** — all alert and tool output is size/type/depth-bounded before crossing into model or report context; the code explicitly does not claim to "stop" prompt injection | `guardrails.sanitize_untrusted_payload`, `sanitize_text` | LLM01 Prompt Injection | AML.T0051 LLM Prompt Injection | MEASURE 2.6; MANAGE 2.2 |
| C6 | **Injection-resistant model boundary** — model proposes only; prompt instructs it to treat data as evidence, never instructions; system prompt states policy retains authority | `model_adapter.JsonModelAdapter._prompt`, `AnthropicModelAdapter` | LLM01 Prompt Injection | AML.T0051 | GOVERN 3.2; MEASURE 2.6 |
| C7 | **Output validation** — every model output (plan, correlation, verdict) is validated against a strict Pydantic schema (`extra="forbid"`) before use | `guardrails.InvestigationPlan/Correlation/Verdict`, `graph.*_node` | LLM05 Improper Output Handling | Model output manipulation | MEASURE 2.3; MANAGE 2.2 |
| C8 | **Human approval, fail-closed** — high-impact containment recommendations pause for a human; timeout or malformed response denies | `graph.human_approval_node` (`interrupt`), `guardrails.validate_approval` | LLM06 Excessive Agency | Human-in-the-loop control | GOVERN 3.2; MANAGE 2.3 |
| C9 | **Request-only containment** — the containment tool produces a recommendation only; no code path performs a real account action | `mcp_server.recommend_account_containment`, `graph.report_node` (`runtime_effect`) | LLM06 Excessive Agency | Unauthorized action | MANAGE 2.4 |
| C10 | **Least-privilege secrets & network** — no secrets in code; model keys from env only; Ollama restricted to loopback; no runtime network egress in the default profile (the optional Anthropic adapter opts into an external API call) | `model_adapter` (env keys, loopback check); `.gitignore`; stub + stdio MCP | LLM02; LLM03 | Credential access prevention | GOVERN 6.1; MANAGE 2.2 |
| C11 | **Audit trail** — each node decision, successful tool call, and approval emits a structured, additive audit event (denied tool calls fail closed by raising, before a node-level event) | `graph._event`, `TriageState.audit_log` | LLM06 (accountability) | Monitoring & detection | MEASURE 2.8; GOVERN 4.2 |
| C12 | **Bounded autonomy** — one containment recommendation per run; read-only enrichment fans out in parallel but cannot escalate | `graph.risk_gate_node`, manifest `limits` | LLM10 Unbounded Consumption | Runaway autonomy | MANAGE 2.4 |

Framework citations are representative anchors, not exhaustive coverage claims. OWASP and NIST
entries use official identifiers; ATLAS entries cite the formal technique where one directly applies
(e.g., AML.T0051 LLM Prompt Injection) and otherwise name the relevant adversary or mitigation
concept, not a claimed technique ID. The point of this
matrix is falsifiability: each control is a place in the code, and `validate.py` verifies the code
still contains it. cATO relevance: C8 and C11 illustrate the kind of human-approval and audit evidence a
continuous-authorization (cATO) posture relies on.
