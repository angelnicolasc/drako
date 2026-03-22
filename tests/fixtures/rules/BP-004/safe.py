# ok: BP-004
# Tools defined with timeout mechanism
import asyncio


def tool(func):
    return func


@tool
async def search_web(query: str) -> str:
    """Search the web with a timeout."""
    import aiohttp
    async with aiohttp.ClientSession() as session:
        result = await asyncio.wait_for(
            session.get(f"https://api.example.com/search?q={query}"),
            timeout=30,
        )
        return await result.text()
