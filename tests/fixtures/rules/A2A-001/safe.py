# ok: A2A-001
# Multi-agent system WITH agent-to-agent authentication
from crewai import Agent

researcher = Agent(name="researcher", role="Research Agent")
writer = Agent(name="writer", role="Writing Agent")

# A2A auth configured: mutual_auth via DID exchange
mutual_auth = {
    "method": "did_exchange",
    "verify_agent_identity": True,
    "auto_rotate": True,
}

researcher.delegate(task="write_report", to=writer, a2a_auth=mutual_auth)
