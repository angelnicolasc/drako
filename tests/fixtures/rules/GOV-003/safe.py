# ok: GOV-003
# Tools with rate limiting configured
from crewai import Agent
from crewai_tools import tool

max_calls = 10
rate_limit = 60


@tool
def search_web(query: str) -> str:
    return f"Results for {query}"


agent = Agent(name="searcher", tools=[search_web])
