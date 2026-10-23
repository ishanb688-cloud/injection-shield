import re
import sys
import requests
from bs4 import BeautifulSoup, Comment

# (category, points, pattern)
PATTERNS = [
    ("override", 3, r"ignore\s+(all\s+)?(your\s+)?(previous|prior|earlier|above)\s+(instructions|rules|prompts?)"),
    ("override", 3, r"disregard\s+(all\s+)?(your\s+)?(previous|prior|earlier|above)\s+(instructions|rules)"),
    ("addresses_ai", 2, r"(note|message|instruction|reminder)s?\s+(to|for)\s+(the\s+)?(ai|assistant|model|llm|agent)"),
    ("addresses_ai", 2, r"\bassistant\s*:"),
    ("addresses_ai", 2, r"(requirement|rule|step)s?\s+for\s+the\s+(ai|assistant|model|agent)"),
    ("addresses_ai", 2, r"system\s+(notice|message|override|prompt)"),
    ("secret_request", 2, r"account[_\s]?token|(private\s+)?user\s+profile|private\s+profile"),
    ("secret_request", 1, r"password|secret|credentials|api[_\s]?key"),
    ("output_control", 2, r"(end|finish|conclude)\s+(your\s+)?(summary|answer|response|reply)\s+with"),
    ("output_control", 2, r"(add|append|include|print)\s+(one\s+)?(final|last|extra)\s+line"),
    ("output_control", 1, r"this\s+exact\s+line"),
    ("data_leak_link", 3, r"!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*\)"),
    ("exfiltration", 3, r"(send|email|post|forward|upload)\s+.{0,40}\s+to\s+(https?://|[\w.-]+@)"),
]


def scan_text(text):
    findings = []
    seen = set()
    for category, points, pattern in PATTERNS:
        for m in re.finditer(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            snippet = " ".join(m.group(0).split())
            key = (category, snippet.lower())
            if key in seen:
                continue
            seen.add(key)
            findings.append({"category": category, "points": points, "match": snippet})
    return findings


def verdict_for(score):
    if score >= 5:
        return "DANGEROUS"
    if score >= 3:
        return "SUSPICIOUS"
    return "SAFE"


def page_text(html):
    soup = BeautifulSoup(html, "html.parser")
    comments = [c.strip() for c in soup.find_all(string=lambda s: isinstance(s, Comment))]
    return soup.get_text(separator="\n") + "\n" + "\n".join(comments)


def analyze_page(html):
    findings = scan_text(page_text(html))
    score = sum(f["points"] for f in findings)
    return {"verdict": verdict_for(score), "score": score, "findings": findings}


def load_html(source):
    if source.startswith("http"):
        r = requests.get(source, timeout=15)
        r.raise_for_status()
        return r.text
    with open(source, encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python shield/instruction_language.py <file_or_url>")
    result = analyze_page(load_html(sys.argv[1]))
    print(f"VERDICT: {result['verdict']} (score {result['score']})")
    for f in result["findings"]:
        print(f"  [{f['category']} +{f['points']}] \"{f['match'][:80]}\"")