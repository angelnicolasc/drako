# ok: SEC-002
# Prompt without any secret references
from crewai import Agent

researcher = Agent(
    name="researcher",
    system_prompt="You are a helpful research assistant. Summarize the given documents accurately.",
)
