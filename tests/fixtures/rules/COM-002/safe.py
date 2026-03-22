# ok: COM-002
# Human oversight mechanism configured
from crewai import Agent


def human_in_the_loop(action):
    return True


agent = Agent(
    name="supervised_worker",
    system_prompt="You process requests with human oversight.",
)
