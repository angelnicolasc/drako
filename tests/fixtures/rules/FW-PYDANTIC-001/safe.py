"""FW-PYDANTIC-001 safe: tool returns a validated Pydantic BaseModel."""

from pydantic import BaseModel
from pydantic_ai import Agent


class SearchResult(BaseModel):
    query: str
    results: list[str]


my_agent = Agent("openai:gpt-4o", system_prompt="You are a search assistant.")


@my_agent.tool
def search_web(query: str) -> SearchResult:
    """Search the web and return validated results."""
    return SearchResult(results=["result1", "result2"], query=query)
