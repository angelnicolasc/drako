# ruleid: ID-001
# Static / hardcoded credentials in agent code
from crewai import Agent

api_key = "sk-abc123XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
token = "ghp-myStaticToken1234567890"

agent = Agent(name="assistant", role="Helper", api_key=api_key)
agent.run(task="Summarize documents")
