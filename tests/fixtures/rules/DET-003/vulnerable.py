from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4", temperature=0)
response = llm.invoke("Summarize the latest news")
print(response.content)
