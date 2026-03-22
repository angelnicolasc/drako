# ok: SEC-001
# API keys loaded from environment variables
import os

api_key = os.environ["OPENAI_API_KEY"]
secret_key = os.getenv("SECRET_KEY", "")
