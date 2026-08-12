# Architecture

The defensive SOC triage flow — the model proposes, deterministic policy (`guardrails.py`)
authorizes, MCP tools execute over local stdio, and a human approves anything consequential.
The model holds no authority.

```mermaid
flowchart TB
  A["SOC analyst: suspicious-login alert"]:::human --> I

  I["intake<br/>validate_alert + authorize_triage"]:::code
  I -->|authorized| P
  I -->|invalid or out of scope| B["block: status = blocked"]:::denied

  P["plan<br/>MODEL proposes read-only tools"]:::model --> E
  E["enrich<br/>run 4 read-only MCP tools:<br/>identity_lookup, signin_history,<br/>ip_reputation, siem_recent_events"]:::code --> C
  C["correlate<br/>MODEL proposes risk score"]:::model --> V
  V["verdict<br/>MODEL proposes label, Pydantic-validated"]:::model --> G

  G{"risk_gate<br/>likely-compromise?"}:::code
  G -->|report-only| R
  G -->|likely-compromise| CR["containment recommendation<br/>recommend_account_containment (MCP)<br/>request-only, actioned = false"]:::code
  CR --> H["human_approval<br/>interrupt + validate_approval, fail-closed"]:::human
  H --> R["report<br/>normalized report + audit trail<br/>recorded only, no real action"]:::code

  B --> Z([END])
  R --> Z

  POL["Deterministic policy: guardrails.py<br/>holds all authority — every gate defers to it<br/>allowlists, extra=forbid, complete mediation"]:::policy
  I -.- POL
  E -.- POL
  CR -.- POL
  H -.- POL

  MOD["Model boundary: model_adapter.py<br/>stub Phase 1, Anthropic Phase 2 — proposes only"]:::model
  P -.- MOD
  C -.- MOD
  V -.- MOD

  classDef code fill:#EAF2FF,stroke:#275D9F,color:#0C3D78;
  classDef model fill:#F3ECFF,stroke:#7142C6,color:#4E1D86;
  classDef human fill:#FFF4DC,stroke:#D78300,color:#6B4100;
  classDef denied fill:#FFF0F0,stroke:#D92D20,color:#A01818;
  classDef policy fill:#E8F7F4,stroke:#148373,color:#074D45;
```
