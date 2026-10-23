"""LangGraph workflow: the model proposes; deterministic code retains authority."""

from __future__ import annotations

import asyncio
import operator
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal, TypedDict

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command, interrupt
from pydantic import ValidationError

from .guardrails import (
    Correlation,
    InvestigationPlan,
    PolicyDenied,
    Verdict,
    authorize_triage,
    validate_alert,
    validate_approval,
)
from .mcp_client import enrich_alert, request_containment_recommendation
from .model_adapter import get_model_adapter


class TriageState(TypedDict, total=False):
    alert: dict[str, Any]
    model_name: str
    authorized: bool
    blocked: bool
    block_reason: str
    status: str
    plan: dict[str, Any]
    enrichments: dict[str, Any]
    correlation: dict[str, Any]
    verdict: dict[str, Any]
    containment_required: bool
    containment_recommendation: dict[str, Any]
    approval_timeout_seconds: int
    approval_deadline: str
    approval: dict[str, Any]
    report: dict[str, Any]
    audit_log: Annotated[list[dict[str, Any]], operator.add]


def _event(node: str, decision: str, detail: str) -> dict[str, Any]:
    return {
        "at": datetime.now(UTC).isoformat(),
        "node": node,
        "decision": decision,
        "detail": detail,
    }


def intake_node(state: TriageState) -> dict[str, Any]:
    """Validate the incoming alert and decide whether it is in scope for triage."""
    try:
        alert = validate_alert(state["alert"])
    except (ValidationError, ValueError) as exc:
        return {
            "authorized": False,
            "blocked": True,
            "block_reason": f"alert validation failed: {exc}",
            "audit_log": [
                _event("intake", "blocked", "alert failed deterministic validation")
            ],
        }
    authorized, reason = authorize_triage(alert)
    return {
        "alert": alert,
        "authorized": authorized,
        "blocked": not authorized,
        "block_reason": "" if authorized else reason,
        "status": "authorized" if authorized else "blocked",
        "audit_log": [
            _event("intake", "authorized" if authorized else "blocked", reason)
        ],
    }


def route_after_intake(state: TriageState) -> Literal["plan", "block"]:
    """Send authorized alerts on to planning; everything else to the block node."""
    return "plan" if state.get("authorized") else "block"


def block_node(state: TriageState) -> dict[str, Any]:
    """Record why an alert was refused and end the run."""
    return {
        "blocked": True,
        "status": "blocked",
        "audit_log": [
            _event("block", "ended", state.get("block_reason", "policy denied triage"))
        ],
    }


def plan_node(state: TriageState) -> dict[str, Any]:
    """Ask the model to propose which read-only tools to gather."""
    adapter = get_model_adapter(state.get("model_name"))
    plan = adapter.propose_plan(state["alert"])
    validated = InvestigationPlan.model_validate(plan).model_dump(mode="json")
    return {
        "plan": validated,
        "audit_log": [
            _event(
                "plan", "proposed", f"read-only tools: {', '.join(validated['tools'])}"
            )
        ],
    }


def enrich_node(state: TriageState) -> dict[str, Any]:
    """Run the proposed read-only tools and collect their evidence."""
    outputs = asyncio.run(
        enrich_alert(
            state["alert"],
            state["plan"]["tools"],
            triage_authorized=state["authorized"],
        )
    )
    events = [
        _event(
            "enrich",
            "tool_call_allowed",
            f"{name} returned bounded structured content",
        )
        for name in outputs
    ]
    return {"enrichments": outputs, "audit_log": events}


def correlate_node(state: TriageState) -> dict[str, Any]:
    """Ask the model to correlate the evidence into a risk read."""
    adapter = get_model_adapter(state.get("model_name"))
    correlation = adapter.correlate(state["alert"], state["enrichments"])
    validated = Correlation.model_validate(correlation).model_dump(mode="json")
    return {
        "correlation": validated,
        "audit_log": [
            _event(
                "correlate", "completed", f"risk_score={validated['risk_score']:.2f}"
            )
        ],
    }


def verdict_node(state: TriageState) -> dict[str, Any]:
    """Turn the correlation into a verdict and validate it against the schema."""
    adapter = get_model_adapter(state.get("model_name"))
    correlation = Correlation.model_validate(state["correlation"])
    verdict = adapter.propose_verdict(correlation)
    validated = Verdict.model_validate(verdict).model_dump(mode="json")
    return {
        "verdict": validated,
        "audit_log": [
            _event(
                "verdict",
                "validated",
                f"label={validated['label']}; confidence={validated['confidence']:.2f}",
            )
        ],
    }


def risk_gate_node(state: TriageState) -> dict[str, Any]:
    """Decide whether the verdict warrants a request-only containment recommendation."""
    needs_containment = state["verdict"]["label"] == "likely-compromise"
    if not needs_containment:
        return {
            "containment_required": False,
            "audit_log": [
                _event(
                    "risk_gate",
                    "report_only",
                    "verdict does not meet containment threshold",
                )
            ],
        }
    recommendation = asyncio.run(
        request_containment_recommendation(
            state["alert"],
            state["verdict"]["label"],
            triage_authorized=state["authorized"],
        )
    )
    timeout_seconds = max(0, min(int(state.get("approval_timeout_seconds", 300)), 3600))
    deadline = datetime.now(UTC) + timedelta(seconds=timeout_seconds)
    return {
        "containment_required": True,
        "containment_recommendation": recommendation,
        "approval_deadline": deadline.isoformat(),
        "audit_log": [
            _event(
                "risk_gate",
                "approval_required",
                "request-only recommendation created; no account change performed",
            )
        ],
    }


def route_after_risk_gate(state: TriageState) -> Literal["human_approval", "report"]:
    """Route likely-compromise cases to human approval; otherwise go straight to report."""
    return "human_approval" if state.get("containment_required") else "report"


def human_approval_node(state: TriageState) -> dict[str, Any]:
    """Pause for the analyst's decision, then apply it while failing closed."""
    response = interrupt(
        {
            "question": "Approve, edit, or reject the request-only containment recommendation?",
            "recommendation": state["containment_recommendation"],
            "expires_at": state["approval_deadline"],
            "fail_closed": True,
        }
    )
    approval = validate_approval(response, expires_at=state["approval_deadline"])
    recommendation = dict(state["containment_recommendation"])
    if approval["status"] == "approved":
        if approval.get("edited_actions"):
            recommendation["actions"] = approval["edited_actions"]
        recommendation["actioned"] = True
        recommendation["action_status"] = "approved-for-recording"
    else:
        recommendation["actioned"] = False
        recommendation["action_status"] = "not-actioned"
    return {
        "approval": approval,
        "containment_recommendation": recommendation,
        "audit_log": [
            _event(
                "human_approval",
                approval["status"],
                f"{approval['reason']}; recommendation actioned={recommendation['actioned']}",
            )
        ],
    }


def report_node(state: TriageState) -> dict[str, Any]:
    """Assemble the normalized incident report and its audit trail."""
    report = {
        "report_version": "1.0",
        "alert_id": state["alert"]["alert_id"],
        "status": "completed",
        "scope": "synthetic defensive identity triage",
        "verdict": state["verdict"],
        "evidence": state["enrichments"],
        "containment": state.get("containment_recommendation"),
        "approval": state.get("approval", {"status": "not-required"}),
        "runtime_effect": "recommendation recorded only; no real account action exists",
        "audit_event_count": len(state.get("audit_log", [])) + 1,
    }
    return {
        "status": "completed",
        "report": report,
        "audit_log": [
            _event("report", "emitted", "normalized incident report created")
        ],
    }


def _is_pure_resume(input: Any) -> bool:
    return (
        isinstance(input, Command)
        and input.resume is not None
        and not input.update
        and not input.goto
    )


class SingleRunGraph(CompiledStateGraph):
    """A compiled graph that refuses a fresh start on a thread that already has one.

    ``audit_log`` is additive, so LangGraph would append a second run to the first
    run's trail. The check runs before the Pregel loop opens, because the loop saves
    an input checkpoint before the first node executes; a refusal raised inside a
    node is too late to keep the stored record unchanged. Only a pure resume
    ``Command`` passes through; one that also updates state or jumps to a node
    would change the record and is treated as a start. A saver that cannot be
    read raises, which refuses the start.
    """

    def _saver_for_start(self, input: Any, config: Any) -> BaseCheckpointSaver | None:
        if _is_pure_resume(input) or not config:
            return None
        if (config.get("configurable") or {}).get("thread_id") is None:
            return None
        saver = self.checkpointer
        return saver if isinstance(saver, BaseCheckpointSaver) else None

    @staticmethod
    def _refuse(config: Any) -> None:
        thread_id = config["configurable"]["thread_id"]
        raise PolicyDenied(
            f"thread {thread_id} already has a recorded run; use a new thread id"
        )

    def stream(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        saver = self._saver_for_start(input, config)
        if saver is not None and saver.get_tuple(config) is not None:
            self._refuse(config)
        return super().stream(input, config, **kwargs)

    async def astream(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        saver = self._saver_for_start(input, config)
        if saver is not None and await saver.aget_tuple(config) is not None:
            self._refuse(config)
        async for item in super().astream(input, config, **kwargs):
            yield item


def build_graph(checkpointer: Any = None) -> Any:
    """Wire the nodes and edges into a compiled, runnable graph."""
    builder = StateGraph(TriageState)
    builder.add_node("intake", intake_node)
    builder.add_node("block", block_node)
    builder.add_node("plan", plan_node)
    builder.add_node("enrich", enrich_node)
    builder.add_node("correlate", correlate_node)
    builder.add_node("verdict", verdict_node)
    builder.add_node("risk_gate", risk_gate_node)
    builder.add_node("human_approval", human_approval_node)
    builder.add_node("report", report_node)
    builder.add_edge(START, "intake")
    builder.add_conditional_edges("intake", route_after_intake)
    builder.add_edge("block", END)
    builder.add_edge("plan", "enrich")
    builder.add_edge("enrich", "correlate")
    builder.add_edge("correlate", "verdict")
    builder.add_edge("verdict", "risk_gate")
    builder.add_conditional_edges("risk_gate", route_after_risk_gate)
    builder.add_edge("human_approval", "report")
    builder.add_edge("report", END)
    app = builder.compile(checkpointer=checkpointer)
    app.__class__ = SingleRunGraph  # compile() offers no hook for a subclass
    return app


# Agent Server supplies its own checkpointer. CLI and tests call build_graph with an explicit saver.
graph = build_graph()
