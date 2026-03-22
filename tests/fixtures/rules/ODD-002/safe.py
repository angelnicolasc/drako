# ok: ODD-002
# Agent with tools and a permitted_tools allowlist configured
from crewai import Agent

permitted_tools = ["search_web", "read_url"]

researcher = Agent(
    name="researcher",
    tools=permitted_tools,
)
