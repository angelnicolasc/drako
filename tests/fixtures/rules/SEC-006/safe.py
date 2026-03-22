# ok: SEC-006
# Tool with type annotations and input validation
from crewai import Agent
from crewai_tools import tool


@tool
def search_database(query: str, limit: int = 10) -> str:
    if not isinstance(query, str) or len(query) > 1000:
        raise ValueError("Invalid query")
    return f"Results for {query}"


agent = Agent(name="searcher", tools=[search_database])
