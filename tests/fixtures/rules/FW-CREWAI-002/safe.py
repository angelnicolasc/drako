"""FW-CREWAI-002 safe: memory enabled WITH per-agent isolation via memory_config."""

from crewai import Agent, Task, Crew
from crewai.memory import ShortTermMemory, LongTermMemory, EntityMemory

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

# memory=True with explicit memory_config providing per-agent isolation
# through separate memory store instances.
crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, writing_task],
    memory=True,
    memory_config={
        "short_term": ShortTermMemory(),
        "long_term": LongTermMemory(),
        "entity": EntityMemory(),
    },
    verbose=True,
)

result = crew.kickoff()
