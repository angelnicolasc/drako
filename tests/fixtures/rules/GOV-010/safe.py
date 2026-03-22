# ok: GOV-010
# Escalation path defined for agents
from crewai import Agent


def escalation_policy(error):
    notify_admin(error)


def notify_admin(error):
    pass


agent = Agent(
    name="processor",
    system_prompt="You process data and generate reports.",
)
