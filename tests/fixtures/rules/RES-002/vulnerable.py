# ruleid: RES-002
# No progress snapshots or recovery points on agent failure
from crewai import Agent

agent = Agent(name="researcher", role="Research Agent")

# Long-running task with no way to resume after a crash
agent.run(task="Analyze 10,000 documents and produce summary report")
