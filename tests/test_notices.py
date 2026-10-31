import pytest

import notices
from notices import EXAMPLE_OFFICIAL, SAMPLES, analyze, clean_official, edit_distance, imitates, is_official


@pytest.mark.parametrize("sample", [s for s in SAMPLES if s["kind"] == "real"], ids=lambda s: s["title"])
def test_real_style_notices_have_no_red_flags(sample):
    assert analyze(sample["text"], EXAMPLE_OFFICIAL)["verdict"] == "NO RED FLAGS"


@pytest.mark.parametrize("sample", [s for s in SAMPLES if s["kind"] == "fake"], ids=lambda s: s["title"])
def test_fake_messages_are_flagged(sample):
    assert analyze(sample["text"], EXAMPLE_OFFICIAL)["verdict"] == "LIKELY FAKE"


def test_checker_never_claims_a_message_is_real():
    verdicts = {analyze(s["text"], EXAMPLE_OFFICIAL)["verdict"] for s in SAMPLES}
    assert verdicts <= {"NO RED FLAGS", "SUSPICIOUS", "LIKELY FAKE"}


def test_official_link_gives_a_positive_note():
    text = "Track it at https://www.examplebank.com/track."
    result = analyze(text, "examplebank.com")
    assert result["positives"] and result["verdict"] == "NO RED FLAGS"


def test_lookalike_link_is_caught_only_with_the_official_domain():
    text = "Your refund is ready: https://examplebank.refund-support.com/claim"
    assert analyze(text, "examplebank.com")["verdict"] == "LIKELY FAKE"
    assert analyze(text)["verdict"] == "SUSPICIOUS"


def test_otp_warning_is_not_mistaken_for_a_request():
    text = "Never share your OTP, PIN or CVV with anyone."
    assert analyze(text)["verdict"] == "NO RED FLAGS"


@pytest.mark.parametrize("raw,expected", [
    ("", ""),
    ("examplebank.com", "examplebank.com"),
    ("https://www.ExampleBank.com/login?x=1", "examplebank.com"),
    ("not a domain", None),
    ("localhost", None),
])
def test_clean_official(raw, expected):
    assert clean_official(raw) == expected


def test_invalid_official_domain_is_reported():
    assert any("not understood" in n for n in analyze("hello there", "not a domain")["notes"])


def test_no_link_note_when_official_given():
    assert any("no link" in n for n in analyze("hello there friend", "examplebank.com")["notes"])


def test_is_official_requires_a_real_subdomain_boundary():
    assert is_official("www.examplebank.com", "examplebank.com")
    assert not is_official("evilexamplebank.com", "examplebank.com")
    assert not is_official("examplebank.com.evil.xyz", "examplebank.com")


@pytest.mark.parametrize("host", [
    "examplebank-kyc.xyz", "examp1ebank.com", "examplebank.refund.com", "secure-examplebank.net",
])
def test_imitations(host):
    assert imitates(host, "examplebank.com")


def test_unrelated_hosts_are_not_imitations():
    assert not imitates("bit.ly", "examplebank.com")
    assert not imitates("example.org", "examplebank.com")


def test_edit_distance():
    assert edit_distance("kitten", "sitting") == 3
    assert edit_distance("same", "same") == 0


def test_message_is_truncated_not_crashed():
    assert analyze("a" * (notices.MAX_TEXT * 3))["verdict"] == "NO RED FLAGS"
