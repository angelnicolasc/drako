import httpx

try:
    data = httpx.get("https://api.example.com/data").json()
    print(data)
except httpx.HTTPStatusError as e:
    print(f"HTTP error: {e.response.status_code}")
except httpx.RequestError as e:
    print(f"Request failed: {e}")
