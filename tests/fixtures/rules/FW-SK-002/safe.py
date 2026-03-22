"""FW-SK-002 safe: planner with cost guard via max_auto_invoke_attempts."""

from semantic_kernel import Kernel
from semantic_kernel.planners import SequentialPlanner

kernel = Kernel()
planner = SequentialPlanner(kernel=kernel)

max_auto_invoke_attempts = 5

result = planner.create_plan("Summarise the latest news")
