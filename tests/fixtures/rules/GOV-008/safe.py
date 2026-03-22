# ok: GOV-008
# Critical tool with fallback/retry logic inside function body
from crewai import Agent
from crewai_tools import tool


@tool
def send_email(to: str, body: str) -> str:
    """Send email with retry fallback."""
    try:
        return f"Email sent to {to}"
    except Exception:
        # fallback: retry with backoff
        import time
        time.sleep(1)
        return f"Email sent to {to} (retry)"


agent = Agent(name="mailer", tools=[send_email])
