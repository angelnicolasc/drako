# ruleid: VCR-003
# 3+ vendor layers from Microsoft: AutoGen + Azure OpenAI + Azure Cloud
from autogen import AssistantAgent
import semantic_kernel
from azure.identity import DefaultAzureCredential

AZURE_OPENAI_ENDPOINT = "https://myorg.openai.azure.com"

agent = AssistantAgent(
    name="assistant",
    llm_config={"model": "gpt-4", "api_type": "azure"},
    system_prompt="You are a helpful assistant",
)
