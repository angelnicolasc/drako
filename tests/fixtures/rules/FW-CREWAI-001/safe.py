"""CrewAI agent with code execution in a sandboxed environment."""
from crewai import Agent, Crew, Task

# Using Docker-based sandbox for code execution
researcher = Agent(
    role="researcher",
    goal="Research topics",
    backstory="Expert researcher",
    allow_code_execution=True,
    code_execution_mode="docker",  # Sandboxed execution
)

task = Task(
    description="Research the latest AI trends",
    agent=researcher,
    expected_output="A report",
)

crew = Crew(agents=[researcher], tasks=[task])
