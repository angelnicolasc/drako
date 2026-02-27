"""CrewAI agent in a mixed-framework project."""
import os
from crewai import Agent, Task, Crew

api_key = os.environ.get("OPENAI_API_KEY")

analyst = Agent(
    name="DataAnalyst",
    role="Data Analyst",
    goal="Analyze datasets",
    model="gpt-4o",
    tools=["read_csv", "plot_chart"],
)

task = Task(description="Analyze the dataset", agent=analyst)
crew = Crew(agents=[analyst], tasks=[task])
