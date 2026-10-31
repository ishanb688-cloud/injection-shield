from shield.output_check import check_output

SECRET = "FAKE-TOKEN-7731-DEMO"


def test_secret_is_redacted_everywhere():
    out = check_output(f"Summary.\nReference: {SECRET}", [SECRET])
    assert SECRET not in out["cleaned"]
    assert "[REDACTED]" in out["cleaned"]
    assert [f["type"] for f in out["findings"]] == ["secret_leak"]


def test_secret_match_is_case_insensitive():
    out = check_output(f"code {SECRET.lower()}", [SECRET])
    assert "[REDACTED]" in out["cleaned"]


def test_auto_loading_image_is_removed_and_the_report_does_not_leak():
    answer = f"Done.\n![read](http://localhost:9000/pixel.png?ref={SECRET})"
    out = check_output(answer, [SECRET])
    assert "pixel.png" not in out["cleaned"]
    assert SECRET not in out["cleaned"]
    assert all(SECRET not in f["detail"] for f in out["findings"])
    assert "auto_loading_image" in [f["type"] for f in out["findings"]]


def test_external_link_is_removed_unless_allowed():
    answer = "See http://evil.example/x for more."
    removed = check_output(answer, [SECRET])
    assert "evil.example" not in removed["cleaned"]
    kept = check_output(answer, [SECRET], allowed_domains=["evil.example"])
    assert "evil.example" in kept["cleaned"]


def test_clean_answer_passes_untouched():
    answer = "The monsoon is a good time to plant leafy vegetables."
    out = check_output(answer, [SECRET])
    assert out["findings"] == [] and out["cleaned"] == answer


def test_empty_secret_list_is_safe():
    assert check_output("anything", [])["cleaned"] == "anything"
