import sys
import requests

from assistant import ask_model, DEFAULT_MODELS
from shield.pipeline import inspect
from shield.output_check import check_output

# In a real app these come from the user's private data. Here it is our fake demo token.
SECRETS = ["FAKE-TOKEN-7731-DEMO"]


def main():
    if len(sys.argv) not in (2, 3):
        raise SystemExit("Usage: python protected_assistant.py <page_url> [model_name]")
    url = sys.argv[1]
    models = [sys.argv[2]] if len(sys.argv) == 3 else DEFAULT_MODELS

    r = requests.get(url, timeout=15)
    r.raise_for_status()
    result = inspect(r.text)

    print(f"SHIELD (input): {result['action']}")
    for f in result["hidden"]:
        print(f"  removed hidden content [{f['severity']}]: {'; '.join(f['reasons'])}")
        print(f"      \"{f['text'][:100]}\"")

    if result["action"] == "BLOCK":
        print("  BLOCKED: the visible page text contains instructions aimed at an AI.")
        for f in result["after"]["findings"]:
            print(f"      [{f['category']}] \"{f['match'][:80]}\"")
        return

    answer = ask_model(result["cleaned_text"][:6000], models)
    out = check_output(answer, SECRETS)

    if out["findings"]:
        print("SHIELD (output): LEAK STOPPED")
        for f in out["findings"]:
            print(f"  [{f['severity']}] {f['type']}: {f['detail'][:100]}")
    else:
        print("SHIELD (output): CLEAN")

    print("--- Assistant answer ---")
    print(out["cleaned"])


if __name__ == "__main__":
    main()