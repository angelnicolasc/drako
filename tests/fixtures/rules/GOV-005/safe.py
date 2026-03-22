# ok: GOV-005
# Circuit breaker is configured
import pybreaker

llm_breaker = pybreaker.CircuitBreaker(fail_max=5, reset_timeout=30)


@llm_breaker
def call_llm(prompt):
    return "response"
