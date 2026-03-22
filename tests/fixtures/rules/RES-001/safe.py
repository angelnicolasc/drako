# ok: RES-001
# Critical tools with fallback / error recovery path
from crewai import Agent


def process_payment(amount: float) -> str:
    try:
        result = execute_payment(amount)
        return result
    except Exception:
        # Fallback: escalate to human when payment tool fails
        fallback_action = "escalate_human"
        return graceful_degradation(action=fallback_action)


agent = Agent(
    name="payment_agent",
    role="Payment Processor",
    tools=["transfer_funds", "execute_payment"],
)
agent.run(task="Process customer refund")
