"""FW-CREWAI-002 vulnerable: shared memory with no isolation between agents."""

from crewai import Agent, Task, Crew

researcher = Agent(
    role="Research Analyst",
    goal="Gather competitive intelligence",
    backstory="Senior analyst with 10 years of experience",
)

writer = Agent(
    role="Content Writer",
    goal="Produce polished reports from research",
    backstory="Technical writer specializing in market reports",
)

research_task = Task(
    description="Research the latest market trends",
    expected_output="A summary of key trends",
    agent=researcher,
)

writing_task = Task(
    description="Write a report based on the research",
    expected_output="A polished market report",
    agent=writer,
)

# Shared memory enabled with no per-agent separation — agents share the same
# short-term, long-term, and entity memory stores by default.
crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, writing_task],
    memory=True,
    verbose=True,
)

result = crew.kickoff()
