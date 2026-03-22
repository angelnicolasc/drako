# ruleid: ODD-004
# Agents defined with no execution duration or loop bounds
from crewai import Agent

researcher = Agent(name="researcher", role="Research Agent")
writer = Agent(name="writer", role="Writing Agent")
