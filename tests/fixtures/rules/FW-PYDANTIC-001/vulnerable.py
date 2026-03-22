"""FW-PYDANTIC-001 vulnerable: tool returns unvalidated dict/str."""

from pydantic_ai import Agent

my_agent = Agent("openai:gpt-4o", system_prompt="You are a search assistant.")


@my_agent.tool
def search_web(query: str) -> dict:
    """Search the web and return raw results."""
    return {"results": ["result1", "result2"], "query": query}
