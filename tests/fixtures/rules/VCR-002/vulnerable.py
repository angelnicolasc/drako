# ruleid: VCR-002
# Governance tooling from same vendor as framework
from autogen import AssistantAgent
import semantic_kernel

agent = AssistantAgent(
    name="assistant",
    system_prompt="You are a helpful assistant",
)
