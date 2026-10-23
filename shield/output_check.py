import re
from urllib.parse import urlparse

IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)\s]+\)")
URL_RE = re.compile(r"https?://[^\s)\]>\"']+")


def host_of(url):
    return (urlparse(url).hostname or "").lower()


def check_output(answer, secrets, allowed_domains=()):
    allowed = {d.lower() for d in allowed_domains}
    findings = []
    cleaned = answer

    def redact(text):
        for s in secrets:
            if s:
                text = re.sub(re.escape(s), "[REDACTED]", text, flags=re.IGNORECASE)
        return text

    for img in IMAGE_RE.findall(cleaned):
        findings.append(
            {"type": "auto_loading_image", "severity": "high", "detail": redact(img)}
        )
    cleaned = IMAGE_RE.sub("[image removed by shield]", cleaned)

    for url in URL_RE.findall(cleaned):
        if host_of(url) not in allowed:
            findings.append(
                {"type": "external_link", "severity": "medium", "detail": redact(url)}
            )
            cleaned = cleaned.replace(url, "[link removed by shield]")

    for s in secrets:
        if s and re.search(re.escape(s), cleaned, flags=re.IGNORECASE):
            findings.append(
                {"type": "secret_leak", "severity": "high",
                "detail": "a protected value appears in the answer"}
            )
            cleaned = re.sub(re.escape(s), "[REDACTED]", cleaned, flags=re.IGNORECASE)

    return {"findings": findings, "cleaned": cleaned}