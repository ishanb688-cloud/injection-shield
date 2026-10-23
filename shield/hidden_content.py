import re
import sys
import requests
from bs4 import BeautifulSoup, Comment

ZERO_WIDTH = {
    "\u200b": "zero-width space",
    "\u200c": "zero-width non-joiner",
    "\u200d": "zero-width joiner",
    "\u2060": "word joiner",
    "\ufeff": "zero-width no-break space",
}


def parse_style(style_text):
    rules = {}
    for part in style_text.split(";"):
        if ":" in part:
            name, value = part.split(":", 1)
            rules[name.strip().lower()] = value.strip().lower()
    return rules


def normalize_color(value):
    v = value.replace(" ", "")
    if v in ("white", "#fff", "#ffffff", "rgb(255,255,255)"):
        return "white"
    if v in ("black", "#000", "#000000", "rgb(0,0,0)"):
        return "black"
    return v


def px_value(value):
    if value == "0":
        return 0.0
    m = re.match(r"^(-?\d+(?:\.\d+)?)px$", value)
    return float(m.group(1)) if m else None


def hidden_reasons(tag):
    reasons = []
    if tag.has_attr("hidden"):
        reasons.append("has the 'hidden' attribute")
    rules = parse_style(tag.get("style", ""))
    if rules.get("display") == "none":
        reasons.append("display:none")
    if rules.get("visibility") == "hidden":
        reasons.append("visibility:hidden")
    opacity = rules.get("opacity")
    if opacity is not None:
        try:
            if float(opacity) <= 0.05:
                reasons.append("opacity near zero")
        except ValueError:
            pass
    size = px_value(rules.get("font-size", ""))
    if size is not None and size <= 3:
        reasons.append(f"tiny font ({size:g}px)")
    fg = rules.get("color")
    bg = rules.get("background") or rules.get("background-color")
    if fg and bg and normalize_color(fg) == normalize_color(bg):
        reasons.append("text color matches background")
    for prop in ("left", "top", "text-indent"):
        value = px_value(rules.get(prop, ""))
        if value is not None and value <= -500:
            reasons.append(f"pushed off-screen ({prop}:{value:g}px)")
    return reasons


def find_hidden_content(html):
    soup = BeautifulSoup(html, "html.parser")
    findings = []
    flagged_ids = set()

    for tag in soup.find_all(True):
        if any(id(p) in flagged_ids for p in tag.parents):
            continue
        reasons = hidden_reasons(tag)
        text = tag.get_text(" ", strip=True)
        if reasons and text:
            flagged_ids.add(id(tag))
            findings.append(
                {"type": "hidden_text", "severity": "high", "reasons": reasons, "text": text}
            )

    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        text = c.strip()
        if text:
            findings.append(
                {"type": "html_comment", "severity": "low",
                 "reasons": ["text inside an HTML comment"], "text": text}
            )

    counts = {}
    decoded = []
    for ch in soup.get_text():
        if ch in ZERO_WIDTH:
            counts[ZERO_WIDTH[ch]] = counts.get(ZERO_WIDTH[ch], 0) + 1
        elif 0xE0000 <= ord(ch) <= 0xE007F:
            decoded.append(chr(ord(ch) - 0xE0000))
    if counts:
        summary = ", ".join(f"{n} x {name}" for name, n in counts.items())
        findings.append(
            {"type": "invisible_characters", "severity": "medium",
            "reasons": ["invisible characters in the text"], "text": summary}
        )
    hidden_message = "".join(decoded)
    if hidden_message.strip() and hidden_message.isprintable():
        findings.append(
            {"type": "unicode_tag_message", "severity": "high",
            "reasons": ["a message hidden in invisible Unicode tag characters"],
            "text": hidden_message}
        )
    return findings


def load_html(source):
    if source.startswith("http"):
        r = requests.get(source, timeout=15)
        r.raise_for_status()
        return r.text
    with open(source, encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python shield/hidden_content.py <file_or_url>")
    findings = find_hidden_content(load_html(sys.argv[1]))
    if not findings:
        print("No hidden content found.")
    for f in findings:
        print(f"[{f['severity'].upper()}] {f['type']}: {'; '.join(f['reasons'])}")
        print(f"    -> {f['text'][:200]}")