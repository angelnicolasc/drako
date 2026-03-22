# ruleid: A2A-002
# Agent accepts unvalidated input from other agents (inter-agent data flow)
from crewai import Agent

researcher = Agent(name="researcher", role="Research Agent")
writer = Agent(name="writer", role="Writing Agent")

# Inter-agent delegation without input validation or injection scanning
result = researcher.run(task="Research topic")
writer.delegate(task=result, to=writer)  # agent_output passed as input
