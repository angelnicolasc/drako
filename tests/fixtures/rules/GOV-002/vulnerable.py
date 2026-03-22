# ruleid: GOV-002
# No policy enforcement middleware
from crewai import Agent

agent = Agent(
    name="worker",
    system_prompt="You are a helpful assistant that processes tasks.",
)
