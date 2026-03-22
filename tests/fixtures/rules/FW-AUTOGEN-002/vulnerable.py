"""Vulnerable: GroupChat with no output validation on agent responses."""

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

group_chat = GroupChat(
    agents=[user_proxy, researcher, writer],
    messages=[],
    max_round=10,
)

manager = GroupChatManager(groupchat=group_chat, llm_config=llm_config)

user_proxy.initiate_chat(manager, message="Research and summarize AI safety.")
