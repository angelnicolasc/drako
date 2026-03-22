# ok: SEC-011
# No high-impact tools defined, so intent verification is not required
from crewai import Agent
from crewai_tools import tool


@tool
def lookup_info(query: str) -> str:
    return f"Info for {query}"


agent = Agent(name="helper", tools=[lookup_info])
