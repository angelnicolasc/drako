# ruleid: SEC-010
# No prompt injection defense configured in project
from crewai import Agent

agent = Agent(
    name="assistant",
    system_prompt="You are a helpful assistant that answers questions.",
)
