# ok: VCR-003
# Multi-vendor: CrewAI (independent) + Anthropic model
from crewai import Agent

agent = Agent(
    name="assistant",
    role="Helper",
    model="claude-sonnet-4-20250514",
)
