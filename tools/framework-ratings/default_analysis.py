"""Evaluate framework-level security defaults and produce a score modifier."""

from __future__ import annotations

from framework_configs import FrameworkDefaults

# Penalty applied when the framework enables arbitrary code execution by default.
_CODE_EXEC_PENALTY = -15

# Bonus for each positive governance default present out of the box.
_POSITIVE_DEFAULT_BONUS = 5

# Human-readable labels for each default flag.
_DEFAULT_LABELS: dict[str, str] = {
    "audit_logging": "Audit Logging",
    "tool_permissions": "Tool Permissions",
    "output_validation": "Output Validation",
    "hitl_support": "Human-in-the-Loop",
    "memory_isolation": "Memory Isolation",
    "rate_limiting": "Rate Limiting",
    "credential_management": "Credential Management",
}


def analyze_defaults(defaults: FrameworkDefaults) -> tuple[int, dict]:
    """Score a framework's built-in security defaults.

    Returns a ``(score_modifier, details)`` tuple where *score_modifier* is
    the total point adjustment (can be negative) and *details* is a dict
    describing each evaluated default.
    """
    modifier = 0
    breakdown: dict[str, dict] = {}

    # --- Code execution penalty -------------------------------------------
    if defaults.code_execution_default:
        modifier += _CODE_EXEC_PENALTY
        breakdown["code_execution_default"] = {
            "label": "Code Execution Enabled by Default",
            "enabled": True,
            "impact": _CODE_EXEC_PENALTY,
            "severity": "high",
            "note": (
                "Arbitrary code execution is enabled in the default "
                "configuration, exposing agents to RCE risks."
            ),
        }
    else:
        breakdown["code_execution_default"] = {
            "label": "Code Execution Enabled by Default",
            "enabled": False,
            "impact": 0,
            "severity": "none",
            "note": "Code execution is not enabled by default.",
        }

    # --- Positive defaults ------------------------------------------------
    for field_name, label in _DEFAULT_LABELS.items():
        enabled = getattr(defaults, field_name)
        impact = _POSITIVE_DEFAULT_BONUS if enabled else 0
        modifier += impact
        breakdown[field_name] = {
            "label": label,
            "enabled": enabled,
            "impact": impact,
            "severity": "none" if enabled else "info",
            "note": (
                f"{label} is provided out of the box."
                if enabled
                else f"{label} is not available by default."
            ),
        }

    # --- Summary ----------------------------------------------------------
    positive_count = sum(
        1
        for k, v in breakdown.items()
        if k != "code_execution_default" and v["enabled"]
    )
    total_positives = len(_DEFAULT_LABELS)
    details: dict = {
        "modifier": modifier,
        "breakdown": breakdown,
        "positive_defaults": positive_count,
        "total_possible_positives": total_positives,
        "code_execution_penalty_applied": defaults.code_execution_default,
    }
    return modifier, details
