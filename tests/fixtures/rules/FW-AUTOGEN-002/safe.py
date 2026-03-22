"""Safe: GroupChat with output validation via register_reply."""

from autogen import AssistantAgent, UserProxyAgent, GroupChat, GroupChatManager

llm_config = {"model": "gpt-4", "api_key": "sk-xxx"}

researcher = AssistantAgent(
    name="researcher",
    system_message="You research topics thoroughly.",
    llm_config=llm_config,
)

writer = AssistantAgent(
    name="writer",
    system_message="You write clear summaries.",
    llm_config=llm_config,
)

user_proxy = UserProxyAgent(
    name="user_proxy",
    human_input_mode="NEVER",
)


def sanitize_reply(recipient, messages, sender, config):
    """Validate and sanitize agent output before passing along."""
    last = messages[-1].get("content", "") if messages else ""
    if len(last) > 5000:
        return True, {"content": last[:5000] + "\n[TRUNCATED]"}
    blocked = ["EXECUTE:", "RUN COMMAND:"]
    for term in blocked:
        if term in last:
            return True, {"content": "[BLOCKED] Unsafe output detected."}
    return False, None


researcher.register_reply(AssistantAgent, sanitize_reply, position=0)
writer.register_reply(AssistantAgent, sanitize_reply, position=0)

group_chat = GroupChat(
    agents=[user_proxy, researcher, writer],
    messages=[],
    max_round=10,
)

manager = GroupChatManager(groupchat=group_chat, llm_config=llm_config)

user_proxy.initiate_chat(manager, message="Research and summarize AI safety.")
