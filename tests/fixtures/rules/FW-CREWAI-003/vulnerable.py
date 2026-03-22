"""FW-CREWAI-003 vulnerable: delegation without boundary enforcement.

One agent has allow_delegation=True but not all agents in the file
have an explicit tools= keyword, so delegation boundaries are unguarded.
"""

from crewai import Agent

researcher = Agent(
    role="Researcher",
    goal="Find relevant data",
    backstory="Expert researcher",
    allow_delegation=True,
    tools=[],  # this agent has tools=
)

writer = Agent(
    role="Writer",
    goal="Draft content",
    backstory="Expert writer",
    # NO tools= keyword here -> triggers FW-CREWAI-003
)
