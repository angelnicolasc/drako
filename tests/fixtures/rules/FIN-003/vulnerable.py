# ruleid: FIN-003
# LLM calls without response memoization
import openai
from crewai_tools import tool

client = openai.OpenAI()


@tool
def answer_question(question: str) -> str:
    """Answer a question using the LLM."""
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": question}],
    )
    return response.choices[0].message.content
