# ok: GOV-002
# Policy enforcement configured via governance middleware
from crewai import Agent

governance = True  # policy enforcement is active

agent = Agent(
    name="worker",
    system_prompt="You are a helpful assistant that processes tasks.",
)
