# ruleid: ODD-001
# Agents defined without any operational boundary definition (ODD)
from crewai import Agent

researcher = Agent(name="researcher", role="Research Agent")
writer = Agent(name="writer", role="Writing Agent")
