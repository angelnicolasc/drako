# ruleid: A2A-001
# Multi-agent system with no inter-agent auth configured
from crewai import Agent

researcher = Agent(name="researcher", role="Research Agent")
writer = Agent(name="writer", role="Writing Agent")

# Agents communicate directly with no identity verification
researcher.delegate(task="write_report", to=writer)
