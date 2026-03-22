# ok: GOV-001
# Audit logging configured at infrastructure level
from crewai import Agent

audit_logger = True  # audit logging is set up

agent = Agent(
    name="worker",
    system_prompt="You are a helpful assistant that processes tasks.",
)
