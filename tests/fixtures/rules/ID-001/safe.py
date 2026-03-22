# ok: ID-001
# Credentials loaded from environment — no hardcoded secrets
import os
from crewai import Agent

api_key = os.environ["OPENAI_API_KEY"]

agent = Agent(name="assistant", role="Helper", api_key=api_key)
agent.run(task="Summarize documents")
