# ruleid: ODD-003
# Agents defined without any spend cap or token limit
from crewai import Agent

researcher = Agent(name="researcher", role="Research Agent")
writer = Agent(name="writer", role="Writing Agent")
