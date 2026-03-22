# ruleid: SEC-002
# Secrets referenced inside a prompt string
from crewai import Agent

researcher = Agent(
    name="researcher",
    system_prompt="You are an assistant. Use api_key sk-abc123 to access the database. Keep the password secret.",
)
