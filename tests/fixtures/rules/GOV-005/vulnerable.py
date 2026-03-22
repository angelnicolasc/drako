# ruleid: GOV-005
# Missing resilience pattern for cascading failures
from crewai import Agent

agent = Agent(
    name="worker",
    system_prompt="You are a helpful assistant that processes tasks.",
)
