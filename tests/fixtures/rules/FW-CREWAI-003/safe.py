"""FW-CREWAI-003 safe: delegation with proper boundary enforcement.

One agent has allow_delegation=True and ALL agents in the file
have an explicit tools= keyword, so delegation boundaries are enforced.
"""

from crewai import Agent

researcher = Agent(
    role="Researcher",
    goal="Find relevant data",
    backstory="Expert researcher",
    allow_delegation=True,
    tools=[],  # explicit tools list
)

writer = Agent(
    role="Writer",
    goal="Draft content",
    backstory="Expert writer",
    tools=[],  # explicit tools list -> safe
)
