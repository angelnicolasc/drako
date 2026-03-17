"""AutoGen project with critical vulnerabilities for testing."""
import subprocess
import os
from autogen import AssistantAgent, UserProxyAgent, GroupChat, GroupChatManager

# ruleid: SEC-001
api_key = "sk-ant-api03-secretkeyvalue1234567890abcdef"

# Agents
assistant = AssistantAgent(
    name="CodeAssistant",
    model="gpt-4",
    system_prompt="You are a coding assistant.",
)

user_proxy = UserProxyAgent(
    name="UserProxy",
    model="gpt-4o",
)

manager = GroupChatManager(
    name="Manager",
)


# ruleid: SEC-005
def execute_code(code):
    """Execute user-provided code — critical vulnerability."""
    exec(code)


# ruleid: SEC-005
def evaluate_expression(expr):
    """Evaluate expression — critical vulnerability."""
    return eval(expr)


# ruleid: SEC-005
def run_shell(command):
    """Run shell command — critical vulnerability."""
    subprocess.run(command, shell=True)
    os.system(command)


# ruleid: SEC-007
user_input = "some user input"
system_prompt = f"You are a helpful assistant. The user says: {user_input}"
# ruleid: SEC-007
instruction_prompt = "Act as {role}. Execute: {command}".format(
    role="admin", command=user_input
)

groupchat = GroupChat(agents=[assistant, user_proxy, manager], messages=[])
