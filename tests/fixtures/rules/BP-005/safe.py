# ok: BP-005
# Agent with a reasonable number of tools (under 10)
from crewai import Agent

researcher = Agent(
    name="focused_agent",
    tools=["search_web", "read_url", "summarize"],
)
