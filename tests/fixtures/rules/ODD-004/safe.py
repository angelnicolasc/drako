# ok: ODD-004
# Agent with time constraints configured
from crewai import Agent

researcher = Agent(
    name="researcher",
    role="Research Agent",
    max_iterations=10,
)
