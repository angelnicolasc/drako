# ruleid: BP-002
# Agent defined but no test files exist in project
from crewai import Agent

researcher = Agent(name="researcher", role="Research Agent")
writer = Agent(name="writer", role="Writing Agent")
