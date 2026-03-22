# ruleid: HOOK-002
# Config has pre-action hooks but no session-end gate
from crewai import Agent

agent = Agent(name="assistant", role="Helper")
agent.run(task="Complete user workflow")
