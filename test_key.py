import os
import requests
from dotenv import load_dotenv

load_dotenv()
key = os.getenv("API_KEY")
if not key:
    raise SystemExit("API_KEY not found. Check your .env file.")

MODEL = "gemini-flash-latest"
url = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"

resp = requests.post(
    url,
    headers={"x-goog-api-key": key, "Content-Type": "application/json"},
    json={"contents": [{"parts": [{"text": "Say hello in one short sentence."}]}]},
    timeout=90,
)

print("Status:", resp.status_code)
if resp.status_code == 200:
    print(resp.json()["candidates"][0]["content"]["parts"][0]["text"])
else:
    print(resp.text)