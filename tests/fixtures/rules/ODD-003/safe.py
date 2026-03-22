# ok: ODD-003
# Agent with max_tokens spend cap configured
from crewai import Agent

researcher = Agent(
    name="researcher",
    role="Research Agent",
    max_tokens=4096,
)
