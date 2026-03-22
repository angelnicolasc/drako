# ruleid: BP-004
# Tools defined with no execution time limit


def tool(func):
    return func


@tool
def search_web(query: str) -> str:
    """Search the web for information."""
    import requests
    resp = requests.get(f"https://api.example.com/search?q={query}")
    return resp.text
