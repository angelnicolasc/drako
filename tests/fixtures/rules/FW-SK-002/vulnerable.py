"""FW-SK-002 vulnerable: planner created without any cost guard."""

from semantic_kernel import Kernel
from semantic_kernel.planners import SequentialPlanner

kernel = Kernel()
planner = SequentialPlanner(kernel=kernel)

result = planner.create_plan("Summarise the latest news")
