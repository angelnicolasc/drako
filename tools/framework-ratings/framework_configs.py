"""Framework configurations for governance rating analysis."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FrameworkDefaults:
    """Security and governance defaults provided by a framework out of the box."""

    code_execution_default: bool = False
    audit_logging: bool = False
    tool_permissions: bool = False
    output_validation: bool = False
    hitl_support: bool = False
    memory_isolation: bool = False
    rate_limiting: bool = False
    credential_management: bool = False


@dataclass
class FrameworkConfig:
    """Configuration for scanning and rating a single framework."""

    name: str
    display_name: str
    repo_url: str
    example_paths: list[str] = field(default_factory=list)
    defaults: FrameworkDefaults = field(default_factory=FrameworkDefaults)
    strengths: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Framework definitions
# ---------------------------------------------------------------------------

FRAMEWORKS: list[FrameworkConfig] = [
    FrameworkConfig(
        name="crewai",
        display_name="CrewAI",
        repo_url="https://github.com/crewAIInc/crewAI-examples.git",
        example_paths=[
            "stock_analysis",
            "instagram_post",
            "job-posting",
            "game-builder-crew",
            "trip_planner",
            "marketing_strategy",
        ],
        defaults=FrameworkDefaults(
            code_execution_default=True,
            audit_logging=False,
            tool_permissions=False,
            output_validation=False,
            hitl_support=False,
            memory_isolation=False,
            rate_limiting=False,
            credential_management=False,
        ),
        strengths=[
            "Declarative YAML agent definitions",
            "Built-in role / goal / backstory structure",
            "Task delegation between agents",
            "Growing ecosystem of community tools",
        ],
    ),
    FrameworkConfig(
        name="langgraph",
        display_name="LangGraph",
        repo_url="https://github.com/langchain-ai/langgraph.git",
        example_paths=[
            "examples/multi_agent",
            "examples/chatbots",
            "examples/rag",
            "examples/tool_calling",
            "examples/planning",
        ],
        defaults=FrameworkDefaults(
            code_execution_default=False,
            audit_logging=False,
            tool_permissions=False,
            output_validation=False,
            hitl_support=True,
            memory_isolation=True,
            rate_limiting=False,
            credential_management=False,
        ),
        strengths=[
            "First-class human-in-the-loop via interrupt_before / interrupt_after",
            "Explicit graph-based control flow",
            "Built-in state persistence and checkpointing",
            "Memory isolation through scoped state channels",
        ],
    ),
    FrameworkConfig(
        name="autogen",
        display_name="AutoGen",
        repo_url="https://github.com/microsoft/autogen.git",
        example_paths=[
            "samples/apps/autogen-studio",
            "samples/tools",
            "samples/apps/autogen-assistant",
        ],
        defaults=FrameworkDefaults(
            code_execution_default=True,
            audit_logging=False,
            tool_permissions=False,
            output_validation=False,
            hitl_support=True,
            memory_isolation=False,
            rate_limiting=False,
            credential_management=False,
        ),
        strengths=[
            "Human-in-the-loop approval for code execution",
            "Flexible multi-agent conversation patterns",
            "Docker-based sandboxed code execution option",
            "Strong research community and Microsoft backing",
        ],
    ),
    FrameworkConfig(
        name="semantic-kernel",
        display_name="Semantic Kernel",
        repo_url="https://github.com/microsoft/semantic-kernel.git",
        example_paths=[
            "python/samples/getting_started",
            "python/samples/concepts/auto_function_calling",
            "python/samples/concepts/plugins",
            "python/samples/concepts/agents",
        ],
        defaults=FrameworkDefaults(
            code_execution_default=False,
            audit_logging=True,
            tool_permissions=True,
            output_validation=False,
            hitl_support=True,
            memory_isolation=False,
            rate_limiting=False,
            credential_management=True,
        ),
        strengths=[
            "Function-level access control via kernel filters",
            "Built-in telemetry and observability hooks",
            "Enterprise credential management through Azure identity",
            "Prompt template safety with input validation",
            "Mature plugin permission model",
        ],
    ),
    FrameworkConfig(
        name="pydantic-ai",
        display_name="PydanticAI",
        repo_url="https://github.com/pydantic/pydantic-ai.git",
        example_paths=[
            "examples/pydantic_model",
            "examples/weather_agent",
            "examples/bank_support",
            "examples/sql_gen",
            "examples/rag",
        ],
        defaults=FrameworkDefaults(
            code_execution_default=False,
            audit_logging=False,
            tool_permissions=False,
            output_validation=True,
            hitl_support=False,
            memory_isolation=False,
            rate_limiting=False,
            credential_management=False,
        ),
        strengths=[
            "Type-safe structured outputs via Pydantic models",
            "Compile-time validation of agent response schemas",
            "Dependency injection for tool context",
            "Minimal surface area reduces attack vectors",
        ],
    ),
    FrameworkConfig(
        name="google-adk",
        display_name="Google ADK",
        repo_url="https://github.com/google/adk-python.git",
        example_paths=[
            "examples/basic",
            "examples/tools",
            "examples/multi_agent",
        ],
        defaults=FrameworkDefaults(
            code_execution_default=True,
            audit_logging=True,
            tool_permissions=False,
            output_validation=False,
            hitl_support=False,
            memory_isolation=False,
            rate_limiting=False,
            credential_management=True,
        ),
        strengths=[
            "Built-in session and artifact management",
            "Native Google Cloud integration for credentials",
            "Structured event logging with tracing support",
            "Multi-agent orchestration with routing agents",
        ],
    ),
    FrameworkConfig(
        name="openai-agents",
        display_name="OpenAI Agents SDK",
        repo_url="https://github.com/openai/openai-agents-python.git",
        example_paths=[
            "examples/basic",
            "examples/agent_patterns",
            "examples/tool_use",
            "examples/handoffs",
        ],
        defaults=FrameworkDefaults(
            code_execution_default=False,
            audit_logging=False,
            tool_permissions=False,
            output_validation=True,
            hitl_support=False,
            memory_isolation=False,
            rate_limiting=False,
            credential_management=False,
        ),
        strengths=[
            "Guardrails system for input/output validation",
            "Typed output validation via Pydantic models",
            "Agent handoff pattern for delegation control",
            "Built-in tracing and span-level observability",
        ],
    ),
]


def get_framework_configs(names: list[str] | None = None) -> list[FrameworkConfig]:
    """Return framework configs, optionally filtered by name."""
    if not names:
        return FRAMEWORKS
    name_set = {n.lower().strip() for n in names}
    matched = [fw for fw in FRAMEWORKS if fw.name in name_set]
    if not matched:
        available = ", ".join(fw.name for fw in FRAMEWORKS)
        raise ValueError(f"No matching frameworks. Available: {available}")
    return matched
