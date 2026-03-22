# ruleid: GOV-001
# No audit logging configured
from crewai import Agent

agent = Agent(
    name="worker",
    system_prompt="You are a helpful assistant that processes tasks.",
)
