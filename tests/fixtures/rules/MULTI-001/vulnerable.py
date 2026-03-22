# ruleid: MULTI-001
# Three workers with no fleet-level visibility
from crewai import Agent

researcher = Agent(name="researcher", role="Research Agent")
writer = Agent(name="writer", role="Writing Agent")
reviewer = Agent(name="reviewer", role="Review Agent")
