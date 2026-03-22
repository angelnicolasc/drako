# ruleid: HOOK-001
# Tools defined but no pre-action validation configured
from crewai import Agent
from crewai_tools import tool


@tool
def execute_sql(query: str) -> str:
    """Execute a SQL query."""
    return f"Executed: {query}"


@tool
def file_write(path: str, content: str) -> str:
    """Write content to a file."""
    return f"Written to {path}"


agent = Agent(
    name="assistant",
    role="DB Admin",
    tools=[execute_sql, file_write],
)
