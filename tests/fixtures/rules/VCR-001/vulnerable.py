# ruleid: VCR-001
# Single-vendor stack: AutoGen (microsoft) + Azure OpenAI (microsoft)
from autogen import AssistantAgent

agent = AssistantAgent(
    name="assistant",
    llm_config={"model": "gpt-4", "api_type": "azure"},
    system_prompt="You are a helpful assistant",
)

# Using AzureOpenAI for model API
from langchain_openai import AzureChatOpenAI
llm = AzureChatOpenAI(model="gpt-4")
