# engineering-core

The defensive SOC triage agent: a LangGraph workflow that validates a suspicious-login
alert, gathers evidence through local MCP tools, correlates it, reaches a verdict, and
pauses for human approval before any containment recommendation is recorded. The model
proposes; deterministic policy in `guardrails.py` authorizes every step.

- `src/soc_triage_agent/` — the graph, guardrails, MCP client/server, and model adapters
- `tests/` — control tests covering the guardrail outcomes
- `sample_data/` — synthetic alert and enrichment fixtures

See the repository root `README.md` for the full write-up, and `../governance/` for the
control matrix and framework mappings.
