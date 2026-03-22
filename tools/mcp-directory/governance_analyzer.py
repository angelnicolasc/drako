# mypy: strict
"""Governance characteristic analyzer for MCP servers.

Evaluates 6 dimensions of governance maturity by inspecting
manifest metadata and source code patterns. Uses regex for
TypeScript source (practical compromise — AST parsing TS in
Python adds a heavy dependency for a standalone tool).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from mcp_configs import GovernanceCharacteristic, MCPServerConfig


@dataclass(frozen=True)
class ServerAnalysis:
    """Complete governance analysis result for one MCP server."""

    server_name: str
    category: str
    description: str
    score: int  # 0-100 weighted
    grade: str  # A-F
    characteristics: list[GovernanceCharacteristic]


# ---------------------------------------------------------------------------
# Grade thresholds (reuse Drako's convention)
# ---------------------------------------------------------------------------

def _grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# Pattern detectors (TypeScript-focused regex)
# ---------------------------------------------------------------------------

# 1. Tool Permissions Model — does manifest/code declare required permissions?
_PERMISSIONS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"allowedDirectories|allowedPaths|permissions", re.IGNORECASE),
    re.compile(r"requiredPermissions|scopes|allowedTools", re.IGNORECASE),
    re.compile(r"\"permissions\"\s*:", re.IGNORECASE),
]

# 2. Audit Logging — structured logging or audit trail
_AUDIT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"console\.(log|info|warn|error)\(", re.IGNORECASE),
    re.compile(r"logger\.(log|info|warn|error|debug)\(", re.IGNORECASE),
    re.compile(r"logging\.(info|warning|error|debug)\(", re.IGNORECASE),
    re.compile(r"audit|trace|telemetry", re.IGNORECASE),
]

# 3. Credential Handling — env vars preferred over hardcoded
_CREDENTIAL_SAFE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"process\.env\[", re.IGNORECASE),
    re.compile(r"process\.env\.", re.IGNORECASE),
    re.compile(r"os\.environ", re.IGNORECASE),
    re.compile(r"getenv\(", re.IGNORECASE),
]
_CREDENTIAL_UNSAFE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'(api_key|apikey|secret|password|token)\s*=\s*["\'][^"\']{8,}', re.IGNORECASE),
]

# 4. Rate Limiting
_RATE_LIMIT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"rate.?limit|throttl|retry.?after|429|too.?many.?requests", re.IGNORECASE),
    re.compile(r"backoff|exponential|delay", re.IGNORECASE),
]

# 5. Input Validation — Zod, JSON Schema, or manual validation
_VALIDATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"zod|z\.object|z\.string|z\.number|z\.array", re.IGNORECASE),
    re.compile(r"jsonSchema|JSON\.parse|ajv|validate", re.IGNORECASE),
    re.compile(r"inputSchema|parameters.*schema", re.IGNORECASE),
]

# 6. Error Boundaries — structured error handling
_ERROR_BOUNDARY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"try\s*\{", re.IGNORECASE),
    re.compile(r"catch\s*\(", re.IGNORECASE),
    re.compile(r"McpError|ToolError|isError|errorCode", re.IGNORECASE),
]


def _check_patterns(
    content: str,
    patterns: list[re.Pattern[str]],
    min_matches: int = 1,
) -> tuple[bool, str]:
    """Check if content matches any patterns. Returns (present, evidence)."""
    matches: list[str] = []
    for pat in patterns:
        found = pat.findall(content)
        matches.extend(found[:3])  # Cap evidence per pattern
    present = len(matches) >= min_matches
    evidence = ", ".join(matches[:5]) if matches else "No matches found"
    return present, evidence


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

def analyze_server(
    config: MCPServerConfig,
    manifest_content: str,
    source_content: str,
) -> ServerAnalysis:
    """Analyze a single MCP server for governance characteristics.

    Args:
        config: Server configuration metadata.
        manifest_content: Raw content of package.json / manifest.
        source_content: Concatenated source files (entry point + extras).

    Returns:
        ServerAnalysis with scored characteristics and overall grade.
    """
    combined = manifest_content + "\n" + source_content
    characteristics: list[GovernanceCharacteristic] = []

    # 1. Tool Permissions Model (weight: 20)
    present, evidence = _check_patterns(combined, _PERMISSIONS_PATTERNS)
    characteristics.append(GovernanceCharacteristic(
        name="Tool Permissions Model",
        present=present,
        evidence=evidence,
        weight=20,
        score=100 if present else 0,
    ))

    # 2. Audit Logging (weight: 15)
    present, evidence = _check_patterns(source_content, _AUDIT_PATTERNS, min_matches=2)
    characteristics.append(GovernanceCharacteristic(
        name="Audit Logging",
        present=present,
        evidence=evidence,
        weight=15,
        score=100 if present else 0,
    ))

    # 3. Credential Handling (weight: 20)
    safe_present, safe_evidence = _check_patterns(combined, _CREDENTIAL_SAFE_PATTERNS)
    unsafe_present, unsafe_evidence = _check_patterns(combined, _CREDENTIAL_UNSAFE_PATTERNS)
    cred_present = safe_present and not unsafe_present
    cred_evidence = f"Safe: {safe_evidence}" if safe_present else "No env-based credential handling"
    if unsafe_present:
        cred_evidence += f" | UNSAFE: {unsafe_evidence}"
    characteristics.append(GovernanceCharacteristic(
        name="Credential Handling",
        present=cred_present,
        evidence=cred_evidence,
        weight=20,
        score=100 if cred_present else 0,
    ))

    # 4. Rate Limiting (weight: 15)
    present, evidence = _check_patterns(combined, _RATE_LIMIT_PATTERNS)
    characteristics.append(GovernanceCharacteristic(
        name="Rate Limiting",
        present=present,
        evidence=evidence,
        weight=15,
        score=100 if present else 0,
    ))

    # 5. Input Validation (weight: 15)
    present, evidence = _check_patterns(combined, _VALIDATION_PATTERNS)
    characteristics.append(GovernanceCharacteristic(
        name="Input Validation",
        present=present,
        evidence=evidence,
        weight=15,
        score=100 if present else 0,
    ))

    # 6. Error Boundaries (weight: 15)
    present, evidence = _check_patterns(source_content, _ERROR_BOUNDARY_PATTERNS, min_matches=2)
    characteristics.append(GovernanceCharacteristic(
        name="Error Boundaries",
        present=present,
        evidence=evidence,
        weight=15,
        score=100 if present else 0,
    ))

    # Weighted score
    total_weight = sum(c.weight for c in characteristics)
    weighted_score = sum(c.score * c.weight for c in characteristics)
    overall_score = round(weighted_score / total_weight) if total_weight > 0 else 0
    grade = _grade_from_score(overall_score)

    return ServerAnalysis(
        server_name=config.name,
        category=config.category,
        description=config.description,
        score=overall_score,
        grade=grade,
        characteristics=characteristics,
    )
