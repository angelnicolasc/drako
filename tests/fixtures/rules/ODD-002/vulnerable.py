# ruleid: ODD-002
# Agent with tools but no tool allowlist/filter configured
from crewai import Agent

researcher = Agent(
    name="researcher",
    tools=["search_web", "read_url", "execute_sql"],
)
