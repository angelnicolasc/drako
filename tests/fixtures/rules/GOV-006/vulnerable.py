# ruleid: GOV-006
# Agent can modify its own system prompt outside __init__


class MyAgent:
    def __init__(self):
        self.system_prompt = "You are a helpful assistant."

    def update_behavior(self, new_instructions):
        self.system_prompt = new_instructions
