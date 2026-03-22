# ruleid: GOV-003
# Tools defined but no rate limiting
from crewai import Agent
from crewai_tools import tool


@tool
def search_web(query: str) -> str:
    return f"Results for {query}"


agent = Agent(name="searcher", tools=[search_web])
