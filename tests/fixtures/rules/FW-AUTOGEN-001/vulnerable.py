"""Vulnerable: uses LocalCommandLineCodeExecutor without sandboxing."""

from autogen import AssistantAgent, UserProxyAgent
from autogen.coding import LocalCommandLineCodeExecutor

executor = LocalCommandLineCodeExecutor(work_dir="coding")

code_executor_agent = UserProxyAgent(
    name="code_executor_agent",
    code_execution_config={"executor": executor},
)

assistant = AssistantAgent(name="assistant")

code_executor_agent.initiate_chat(
    assistant,
    message="Write a Python script that prints Hello World.",
)
