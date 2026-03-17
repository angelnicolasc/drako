"""Agent class with self-modifying prompt vulnerability."""
from autogen import ConversableAgent


class CustomAgent(ConversableAgent):
    """Agent that can modify its own system prompt."""

    def __init__(self, name, prompt):
        super().__init__(name=name)
        self.system_prompt = prompt  # ok: GOV-006 (in __init__)

    # ruleid: GOV-006
    def update_behavior(self, new_prompt):
        """Dangerous: agent modifies its own prompt at runtime."""
        self.system_prompt = new_prompt

    # ruleid: GOV-006
    def adapt_instructions(self, context):
        """Another self-modification pattern."""
        self.instructions = f"Based on {context}, do the following..."


# ruleid: BP-005
overloaded_agent = ConversableAgent(
    name="OverloadedAgent",
    tools=[
        "tool_1", "tool_2", "tool_3", "tool_4", "tool_5",
        "tool_6", "tool_7", "tool_8", "tool_9", "tool_10",
        "tool_11", "tool_12",
    ],
)
