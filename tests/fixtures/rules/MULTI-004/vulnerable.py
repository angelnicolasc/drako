# ruleid: MULTI-004
# No stress testing or failure simulation configured
from crewai import Agent, Task, Crew

researcher = Agent(name="researcher", role="Research Agent")
writer = Agent(name="writer", role="Writing Agent")

crew = Crew(agents=[researcher, writer])
crew.kickoff()
