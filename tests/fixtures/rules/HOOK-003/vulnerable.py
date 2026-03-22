# ruleid: HOOK-003
# Hook scripts defined without explicit timeout
from crewai import Agent

agent = Agent(name="assistant", role="Helper")
agent.run(task="Execute validated actions")
