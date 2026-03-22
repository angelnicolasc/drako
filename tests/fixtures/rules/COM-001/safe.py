# ok: COM-001
# Automatic logging configured
import logging

logger = logging.getLogger("agent_system")
audit_log = logger

from crewai import Agent

agent = Agent(
    name="processor",
    system_prompt="You process data and generate reports.",
)
