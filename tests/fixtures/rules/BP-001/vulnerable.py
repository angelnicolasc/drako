# ruleid: BP-001
# Using an outdated major version of crewai
from crewai import Agent

# This simulates a project using crewai 0.1.x (outdated vs latest 0.85)
agent = Agent(name="researcher", role="researcher")
