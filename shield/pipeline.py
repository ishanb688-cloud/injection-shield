from bs4 import BeautifulSoup, Comment

from shield.hidden_content import ZERO_WIDTH, find_hidden_content, hidden_reasons
from shield.instruction_language import analyze_page, scan_text, verdict_for


def strip_invisible(text):
    return "".join(
        ch for ch in text
        if ch not in ZERO_WIDTH and not (0xE0000 <= ord(ch) <= 0xE007F)
    )


def sanitize_to_text(html):
    soup = BeautifulSoup(html, "html.parser")
    hidden_tags = [t for t in soup.find_all(True) if hidden_reasons(t)]
    for tag in hidden_tags:
        tag.extract()
    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        c.extract()
    text = soup.get_text(separator="\n", strip=True)
    return strip_invisible(text)


def inspect(html):
    hidden = find_hidden_content(html)
    original = analyze_page(html)
    cleaned_text = sanitize_to_text(html)

    after_findings = scan_text(cleaned_text)
    after_score = sum(f["points"] for f in after_findings)
    after = {
        "verdict": verdict_for(after_score),
        "score": after_score,
        "findings": after_findings,
    }

    if after["verdict"] == "DANGEROUS":
        action = "BLOCK"
    elif hidden:
        action = "CLEANED"
    else:
        action = "ALLOW"

    return {
        "action": action,
        "hidden": hidden,
        "original": original,
        "after": after,
        "cleaned_text": cleaned_text,
    }