# ok: VCR-001
# Multi-vendor: CrewAI (independent) + OpenAI model
from crewai import Agent

agent = Agent(
    name="assistant",
    role="Helper",
    model="gpt-4",
)
