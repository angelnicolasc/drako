# ok: GOV-006
# System prompt is immutable -- only set in __init__


class MyAgent:
    def __init__(self, prompt):
        self._frozen_prompt = prompt

    @property
    def system_prompt(self):
        return self._frozen_prompt

    def run(self, query):
        return f"Processing: {query}"
