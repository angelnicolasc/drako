# ok: RES-002
# State preservation via checkpointing configured
from crewai import Agent
from langgraph.checkpoint.sqlite import SqliteSaver

checkpointer = SqliteSaver.from_conn_string(":memory:")

agent = Agent(name="researcher", role="Research Agent")

# checkpoint / save_state configured for resilience
agent.run(
    task="Analyze 10,000 documents and produce summary report",
    checkpointer=checkpointer,
    checkpoint=True,
)
