import os
import requests
from dotenv import load_dotenv

load_dotenv()
key = os.getenv("API_KEY")
if not key:
    raise SystemExit("API_KEY not found. Check your .env file.")

resp = requests.get(
    "https://generativelanguage.googleapis.com/v1beta/models",
    headers={"x-goog-api-key": key},
    timeout=30,
)

print("Status:", resp.status_code)
if resp.status_code == 200:
    for m in resp.json().get("models", []):
        if "generateContent" in m.get("supportedGenerationMethods", []):
            print(m["name"])
else:
    print(resp.text)