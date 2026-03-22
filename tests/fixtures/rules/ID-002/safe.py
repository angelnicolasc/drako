# ok: ID-002
# Agent has identity / auth configuration defined
from crewai import Agent

identity_config = {
    "agent_id": "agent-001",
    "credentials": "managed",
    "auth": "oauth2",
    "identity_management": True,
}

agent = Agent(name="assistant", role="Helper", identity=identity_config)
agent.run(task="Process user requests")
