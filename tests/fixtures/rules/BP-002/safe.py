# ok: BP-002
# Agent defined with corresponding test file
from crewai import Agent

researcher = Agent(name="researcher", role="Research Agent")

# test_agents.py exists and references "researcher"
