# ok: MAG-002
# Rate limit / max_iterations defined
from crewai import Agent

assistant = Agent(name="assistant", role="General Assistant")
assistant.run(
    task="Process incoming requests",
    max_iterations=50,
    rate_limit=10,  # requests per minute
)
