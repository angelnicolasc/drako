"""CrewAI project with known governance issues for testing."""
from crewai import Agent, Task, Crew

# SEC-001: Hardcoded API key
OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345"

# Agents
research_agent = Agent(
    name="ResearchAgent",
    role="Senior Researcher",
    goal="Find relevant data",
    model="gpt-4o",
    tools=["search_web", "read_file"],
    system_prompt="You are a research assistant.",
)

writer_agent = Agent(
    name="WriterAgent",
    role="Content Writer",
    goal="Write reports",
    model="claude-3-sonnet-20240229",
)

review_agent = Agent(
    name="ReviewAgent",
    role="Quality Reviewer",
    goal="Review content quality",
)

# SEC-007: Prompt injection via f-string
user_query = "analyze this data"
prompt = f"System: You are an assistant. User request: {user_query}"

# SEC-005: Arbitrary code execution
def run_user_code(code_str):
    exec(code_str)

# Tasks
task1 = Task(description="Research the topic", agent=research_agent)
task2 = Task(description="Write the report", agent=writer_agent)

crew = Crew(agents=[research_agent, writer_agent, review_agent], tasks=[task1, task2])
