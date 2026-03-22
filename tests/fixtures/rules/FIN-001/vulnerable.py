# ruleid: FIN-001
# LLM API calls without any spend monitoring
import openai
from crewai_tools import tool


@tool
def summarize(text: str) -> str:
    """Summarize a document using LLM."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": text}],
    )
    return response.choices[0].message.content
