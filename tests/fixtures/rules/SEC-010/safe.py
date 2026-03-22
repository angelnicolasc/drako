# ok: SEC-010
# Prompt injection defense is configured via guardrails
from crewai import Agent

agent = Agent(
    name="assistant",
    system_prompt="You are a helpful assistant that answers questions.",
)

# Defense: input_validation and sanitize_prompt are applied
input_validation = True
sanitize_prompt = True
