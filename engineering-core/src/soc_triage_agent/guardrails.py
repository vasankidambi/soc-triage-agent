"""Deterministic policy and validation at every trust boundary."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

READ_ONLY_TOOLS = frozenset(
    {"identity_lookup", "signin_history", "ip_reputation", "siem_recent_events"}
)
CONTAINMENT_TOOL = "recommend_account_containment"
ALLOWED_CONTAINMENT_ACTIONS = frozenset(
    {"require_password_reset", "revoke_active_sessions", "step_up_authentication"}
)


class PolicyDenied(RuntimeError):
    """Raised when deterministic policy rejects a requested operation."""


class VerdictLabel(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    LIKELY_COMPROMISE = "likely-compromise"


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    alert_id: str = Field(pattern=r"^SYN-ALT-[0-9]{4}-[0-9]{4}$")
    tenant_id: str = Field(pattern=r"^tenant-soc-lab$")
    queue: Literal["identity-security"]
    alert_type: Literal["suspicious-login"]
    data_classification: Literal["synthetic"]
    source: Literal["synthetic-siem"]
    user_id: str = Field(pattern=r"^usr-syn-[0-9]{4}$")
    source_ip: str
    device_id: str = Field(pattern=r"^dev-syn-[a-z0-9-]{3,32}$")
    observed_at: datetime
    summary: str = Field(min_length=1, max_length=500)
    failed_attempts: int = Field(ge=0, le=100)

    @field_validator("source_ip")
    @classmethod
    def validate_documentation_ip(cls, value: str) -> str:
        address = ipaddress.ip_address(value)
        documentation_ranges = (
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        )
        if not any(address in network for network in documentation_ranges):
            raise ValueError("sample alerts must use an RFC 5737 documentation address")
        return value


class InvestigationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    objective: str = Field(min_length=1, max_length=300)
    tools: list[str] = Field(min_length=1, max_length=4)

    @field_validator("tools")
    @classmethod
    def read_only_tools_only(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("investigation plan contains duplicate tools")
        unknown = set(value) - READ_ONLY_TOOLS
        if unknown:
            raise ValueError(
                f"investigation plan requested non-read-only tools: {sorted(unknown)}"
            )
        return value


class Correlation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_score: float = Field(ge=0.0, le=1.0)
    factors: list[str] = Field(min_length=1, max_length=12)
    assessment: str = Field(min_length=1, max_length=1000)


class Verdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: VerdictLabel
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(min_length=1, max_length=12)
    recommended_next_step: str = Field(min_length=1, max_length=500)


class ApprovalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "reject", "timeout"]
    analyst_id: str = Field(default="analyst-local", pattern=r"^[a-z0-9-]{3,64}$")
    edited_actions: list[str] | None = Field(default=None, max_length=3)
    note: str = Field(default="", max_length=300)

    @field_validator("edited_actions")
    @classmethod
    def validate_edited_actions(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return value
        if not value or len(value) != len(set(value)):
            raise ValueError("edited actions must be non-empty and unique")
        unknown = set(value) - ALLOWED_CONTAINMENT_ACTIONS
        if unknown:
            raise ValueError(f"edited actions are outside policy: {sorted(unknown)}")
        return value


def sanitize_text(value: str, *, max_length: int = 2000) -> str:
    """Normalize untrusted text without pretending sanitization stops prompt injection."""
    normalized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    return normalized[:max_length]


def sanitize_untrusted_payload(value: Any, *, depth: int = 0) -> Any:
    """Bound tool and alert data before it crosses into model or report context."""
    if depth > 8:
        raise PolicyDenied("untrusted payload exceeds maximum nesting depth")
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, dict):
        if len(value) > 100:
            raise PolicyDenied("untrusted object has too many fields")
        return {
            sanitize_text(str(key), max_length=100): sanitize_untrusted_payload(
                item, depth=depth + 1
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        if len(value) > 200:
            raise PolicyDenied("untrusted list has too many items")
        return [sanitize_untrusted_payload(item, depth=depth + 1) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise PolicyDenied(
        f"untrusted payload contains unsupported type: {type(value).__name__}"
    )


def validate_alert(raw_alert: dict[str, Any]) -> dict[str, Any]:
    """Validate alert scope and return a JSON-serializable, bounded copy."""
    alert = Alert.model_validate(raw_alert)
    return sanitize_untrusted_payload(alert.model_dump(mode="json"))


def authorize_triage(alert: dict[str, Any]) -> tuple[bool, str]:
    """Authorize only the synthetic identity-security lab queue."""
    required = {
        "tenant_id": "tenant-soc-lab",
        "queue": "identity-security",
        "alert_type": "suspicious-login",
        "data_classification": "synthetic",
        "source": "synthetic-siem",
    }
    mismatches = [
        key for key, expected in required.items() if alert.get(key) != expected
    ]
    if mismatches:
        return (
            False,
            f"alert is outside authorized synthetic scope: {', '.join(mismatches)}",
        )
    return True, "authorized synthetic identity-security triage"


def authorize_tool_call(
    tool_name: str,
    *,
    triage_authorized: bool,
    verdict: str | None = None,
) -> None:
    """Apply complete mediation independently of any model recommendation."""
    if not triage_authorized:
        raise PolicyDenied("tool call denied: triage is not authorized")
    if tool_name in READ_ONLY_TOOLS:
        return
    if tool_name == CONTAINMENT_TOOL and verdict == VerdictLabel.LIKELY_COMPROMISE:
        return
    raise PolicyDenied(f"tool call denied by allowlist or risk policy: {tool_name}")


def validate_approval(
    raw_response: Any,
    *,
    expires_at: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Fail closed on malformed, rejected, or expired approval responses."""
    current = now or datetime.now(UTC)
    try:
        expiry = datetime.fromisoformat(expires_at)
    except (TypeError, ValueError):
        return {
            "status": "denied",
            "reason": "approval deadline is malformed; fail-closed policy applied",
            "analyst_id": "unknown",
            "edited_actions": None,
        }
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    try:
        response = ApprovalResponse.model_validate(raw_response)
    except ValidationError as exc:
        return {
            "status": "denied",
            "reason": "invalid approval response",
            "validation_error": str(exc),
            "analyst_id": "unknown",
            "edited_actions": None,
        }
    if response.decision == "timeout" or current >= expiry:
        return {
            "status": "denied",
            "reason": "approval timed out; fail-closed policy applied",
            "analyst_id": response.analyst_id,
            "edited_actions": None,
            "note": sanitize_text(response.note, max_length=300),
        }
    if response.decision == "reject":
        return {
            "status": "rejected",
            "reason": "analyst rejected the recommendation",
            "analyst_id": response.analyst_id,
            "edited_actions": None,
            "note": sanitize_text(response.note, max_length=300),
        }
    return {
        "status": "approved",
        "reason": "analyst approved the recommendation",
        "analyst_id": response.analyst_id,
        "edited_actions": response.edited_actions,
        "note": sanitize_text(response.note, max_length=300),
    }
