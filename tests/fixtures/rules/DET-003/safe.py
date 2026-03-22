from langchain_openai import ChatOpenAI
from tenacity import retry, stop_after_attempt, wait_exponential


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
def call_llm(prompt: str) -> str:
    llm = ChatOpenAI(model="gpt-4", temperature=0)
    response = llm.invoke(prompt)
    return response.content


result = call_llm("Summarize the latest news")
print(result)
