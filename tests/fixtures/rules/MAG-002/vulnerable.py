# ruleid: MAG-002
# No action frequency or loop bounds defined
from crewai import Agent

assistant = Agent(name="assistant", role="General Assistant")
assistant.run(task="Process all incoming requests indefinitely")
