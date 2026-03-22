import httpx

data = httpx.get("https://api.example.com/data").json()
print(data)
