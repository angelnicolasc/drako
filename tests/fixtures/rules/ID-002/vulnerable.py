# ruleid: ID-002
# Agents without any verification or access management
from crewai import Agent

planner = Agent(name="planner", role="Task Planner")
executor = Agent(name="executor", role="Task Executor")
