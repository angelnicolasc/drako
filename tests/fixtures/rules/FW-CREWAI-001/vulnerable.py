"""CrewAI agent with code execution enabled without isolation."""
from crewai import Agent, Crew, Task

researcher = Agent(
    role="researcher",
    goal="Research topics",
    backstory="Expert researcher",
    allow_code_execution=True,  # VULNERABLE: no sandbox
)

task = Task(
    description="Research the latest AI trends",
    agent=researcher,
    expected_output="A report",
)

crew = Crew(agents=[researcher], tasks=[task])
