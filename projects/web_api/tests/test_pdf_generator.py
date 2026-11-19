"""Tests for PDF report rendering: HTML injection / SSRF hardening and Gotenberg call."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from jinja2 import UndefinedError
from markupsafe import Markup
from web_api import pdf_generator
from web_api.pdf_generator import (
    convert_html_to_pdf,
    generate_source_report_pdf,
    render_markdown_safe,
    render_source_report_html,
    render_system_report_html,
)

IFRAME = '<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>'


def _source_report(**overrides) -> dict:
    data = {
        "source": "host-01",
        "generated_at": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        "summary": {"total_files": 3, "total_findings": 2, "verified_true_positives": 1, "not_triaged": 1},
        "risk_indicators": {
            "credentials": {
                "titus_findings": 1,
                "chromium_logins_decrypted": 0,
                "chromium_cookies_decrypted": 0,
                "dpapi_masterkeys_decrypted": 0,
            },
            "sensitive_data": {"yara_matches": 0},
        },
        "findings_detail": {"by_category": {"credential": 2}, "by_severity": {"high": 2}},
        "top_findings": [
            {
                "finding_name": "aws_key",
                "category": "credential",
                "severity": 8,
                "triage_state": "true_positive",
                "file_path": "C:/Users/a/creds.txt",
            }
        ],
        "enrichment_performance": {},
    }
    data.update(overrides)
    return data


def _system_report(**overrides) -> dict:
    data = {
        "generated_at": "2026-01-02 03:04:05 UTC",
        "summary": {"total_sources": 1, "total_files": 3, "total_findings": 2, "verified_true_positives": 1},
        "findings_by_category": {"credential": 2},
        "findings_by_severity": {"high": 2},
        "sources": [
            {
                "source": "host-01",
                "file_count": 3,
                "finding_count": 2,
                "verified_findings": 1,
                "last_activity": "2026-01-01",
            }
        ],
    }
    data.update(overrides)
    return data


# --- render_markdown_safe: malicious input is stripped ---


# Raw HTML is rendered as escaped text (never markup) and markdown-generated markup is
# allowlist-sanitized, so the check is that no live resource-loading or script markup
# survives. URLs may still appear as inert text, exactly as in the frontend.
@pytest.mark.parametrize(
    "payload, forbidden",
    [
        (IFRAME, ["<iframe"]),
        ('<iframe src="http://127.0.0.1:3000/health"></iframe>', ["<iframe"]),
        ("<script>fetch('http://10.0.0.1/')</script>", ["<script"]),
        ('<img src="http://169.254.169.254/latest/meta-data/">', ["<img"]),
        ("![x](http://169.254.169.254/latest/meta-data/)", ["<img", "169.254.169.254"]),
        ('<a href="javascript:alert(1)">click</a>', ['<a href="javascript']),
        ("[click](javascript:alert(1))", ['<a href="javascript']),
        ('<a href="file:///etc/passwd">f</a>', ['<a href="file']),
        ("[f](file:///etc/passwd)", ['<a href="file']),
        ('<p onclick="x()" onmouseover="y()">hi</p>', ["<p onclick", "<p onmouseover"]),
        ('<div style="background:url(http://10.0.0.1/x)">hi</div>', ["<div style"]),
        ('<link rel="stylesheet" href="http://10.0.0.1/a.css">', ["<link"]),
        ("<style>@import url(http://10.0.0.1/a.css);</style>", ["<style"]),
        ('<object data="http://10.0.0.1/"></object><embed src="http://10.0.0.1/">', ["<object", "<embed"]),
        ('<svg><image href="http://10.0.0.1/x"/></svg>', ["<svg", "<image"]),
        (
            '<base href="http://10.0.0.1/"><meta http-equiv="refresh" content="0;url=http://10.0.0.1/">',
            ["<base", "<meta"],
        ),
        ('<form action="http://10.0.0.1/"><input></form>', ["<form", "<input"]),
        ('<video src="http://10.0.0.1/v"></video><audio src="http://10.0.0.1/a"></audio>', ["<video", "<audio"]),
        ('<div markdown="1"><iframe src="http://10.0.0.1/"></iframe></div>', ["<iframe", "<div"]),
    ],
)
def test_render_markdown_safe_strips_dangerous_html(payload, forbidden):
    html = str(render_markdown_safe(f"# Report\n\n{payload}\n\nafter"))
    for needle in forbidden:
        assert needle not in html, f"{needle!r} survived sanitization: {html}"
    assert "<h1>Report</h1>" in html
    assert "after" in html


def test_render_markdown_safe_shows_raw_html_as_text():
    html = str(render_markdown_safe(IFRAME))
    assert "<iframe" not in html
    assert "&lt;iframe" in html


def test_render_markdown_safe_renders_normal_markdown():
    md = (
        "# Title\n\n"
        "## Sub\n\n"
        "Some **bold** and *em* and `inline`.\n\n"
        "- one\n- two\n\n"
        "1. first\n2. second\n\n"
        "| A | B |\n|---|---|\n| 1 | 2 |\n\n"
        "```\ncode block\n```\n\n"
        "> quoted\n\n"
        "---\n\n"
        "[docs](https://example.com/docs) and <mailto:a@example.com>\n"
    )
    html = str(render_markdown_safe(md))
    for expected in [
        "<h1>Title</h1>",
        "<h2>Sub</h2>",
        "<strong>bold</strong>",
        "<em>em</em>",
        "<code>inline</code>",
        "<ul>",
        "<li>one</li>",
        "<ol>",
        "<table>",
        "<th>A</th>",
        "<td>1</td>",
        "<pre><code>code block",
        "<blockquote>",
        "<hr>",
        'href="https://example.com/docs"',
    ]:
        assert expected in html, f"{expected!r} missing from {html}"


def test_render_markdown_safe_line_breaks_kept():
    assert "<br>" in str(render_markdown_safe("line one\nline two"))


@pytest.mark.parametrize(
    "md",
    [
        "Key findings:\n- item one\n- item two",
        "**Key findings:**\n* item one\n* item two",
        "Steps:\n1. item one\n2. item two",
    ],
)
def test_render_markdown_safe_list_directly_after_text(md):
    """LLM output rarely puts a blank line before a list; it must still render as a list."""
    html = str(render_markdown_safe(md))
    assert "<li>item one</li>" in html
    assert "<li>item two</li>" in html
    assert "- item" not in html and "* item" not in html


def test_render_markdown_safe_nested_list_and_strikethrough():
    html = str(render_markdown_safe("- parent\n  - child\n\n~~old~~"))
    assert html.count("<ul>") == 2
    assert "<s>old</s>" in html


def test_render_markdown_safe_returns_markup():
    assert isinstance(render_markdown_safe("hi"), Markup)


@pytest.mark.parametrize("value", [None, "", 123, ["# x"], {"a": 1}])
def test_render_markdown_safe_handles_empty_and_non_string(value):
    assert render_markdown_safe(value) == Markup("")


# --- Template autoescape ---


def test_source_report_escapes_source_name():
    html = render_source_report_html(_source_report(source=IFRAME))
    assert "<iframe" not in html
    assert "&lt;iframe" in html


def test_source_report_escapes_finding_fields():
    finding = {
        "finding_name": "<script>x()</script>",
        "category": "<img src=http://10.0.0.1/>",
        "severity": 9,
        "triage_state": "<b>t</b>",
        "file_path": IFRAME,
    }
    html = render_source_report_html(_source_report(top_findings=[finding]))
    assert "<iframe" not in html
    assert "<script>x()" not in html
    assert "<img" not in html
    assert "&lt;iframe" in html


def test_source_report_escapes_category_keys():
    html = render_source_report_html(_source_report(findings_detail={"by_category": {IFRAME: 2}, "by_severity": {}}))
    assert "<iframe" not in html


def test_source_report_ignores_client_supplied_report_html():
    html = render_source_report_html(_source_report(ai_synthesis={"risk_level": "high", "report_html": IFRAME}))
    assert "<iframe" not in html
    assert "169.254.169.254" not in html
    assert "Risk Level: HIGH" in html


def test_source_report_escapes_risk_level():
    html = render_source_report_html(_source_report(ai_synthesis={"risk_level": IFRAME, "report_markdown": "x"}))
    assert "<iframe" not in html


def test_source_report_sanitizes_ai_markdown_but_keeps_formatting():
    md = f"## Findings\n\n- item **one**\n\n{IFRAME}\n\n<img src='http://169.254.169.254/'>"
    html = render_source_report_html(_source_report(ai_synthesis={"risk_level": "medium", "report_markdown": md}))
    assert "<iframe" not in html
    assert "<img" not in html
    # Injected raw HTML is shown as inert, escaped text
    assert "&lt;iframe" in html
    # Not double-escaped: legitimate markup is real HTML
    assert "<h2>Findings</h2>" in html
    assert "<strong>one</strong>" in html
    assert "&lt;h2&gt;" not in html


@pytest.mark.parametrize("ai_synthesis", [None, {}, "not-a-dict", {"risk_level": "low", "report_markdown": None}])
def test_source_report_handles_missing_or_empty_ai_synthesis(ai_synthesis):
    report = _source_report()
    if ai_synthesis is not None:
        report["ai_synthesis"] = ai_synthesis
    html = render_source_report_html(report)
    assert "Source Report: host-01" in html
    assert "2026-01-02 03:04:05 UTC" in html


def test_source_report_normal_values_render_unchanged():
    html = render_source_report_html(_source_report(source="host & co"))
    assert "Source Report: host &amp; co" in html
    assert "C:/Users/a/creds.txt" in html
    assert "100.0%" in html


def test_system_report_escapes_source_source():
    sources = [{"source": IFRAME, "file_count": 1, "finding_count": 0, "verified_findings": 0, "last_activity": None}]
    html = render_system_report_html(_system_report(sources=sources))
    assert "<iframe" not in html
    assert "&lt;iframe" in html


def test_system_report_normal_render():
    html = render_system_report_html(_system_report())
    assert "host-01" in html
    assert "2026-01-02 03:04:05 UTC" in html


# --- Gotenberg call (mocked; no network) ---


def test_convert_html_to_pdf_posts_to_gotenberg():
    response = MagicMock(status_code=200, content=b"%PDF-1.7")
    with patch.object(pdf_generator.requests, "post", return_value=response) as post:
        assert convert_html_to_pdf("<html></html>") == b"%PDF-1.7"
    args, kwargs = post.call_args
    assert args[0] == pdf_generator.GOTENBERG_URL
    assert kwargs["files"]["index.html"][0] == "index.html"


def test_convert_html_to_pdf_raises_on_error_status():
    response = MagicMock(status_code=500, text="boom")
    with patch.object(pdf_generator.requests, "post", return_value=response):
        with pytest.raises(Exception, match="Gotenberg returned status 500"):
            convert_html_to_pdf("<html></html>")


def test_generate_source_report_pdf_sends_sanitized_html():
    sent = {}

    def fake_post(url, files, data, timeout):
        sent["html"] = files["index.html"][1].read().decode()
        return MagicMock(status_code=200, content=b"%PDF")

    report = _source_report(source=IFRAME, ai_synthesis={"risk_level": "high", "report_markdown": IFRAME})
    with patch.object(pdf_generator.requests, "post", side_effect=fake_post):
        assert generate_source_report_pdf(report) == b"%PDF"
    assert "<iframe" not in sent["html"]


# Exactly the credential keys reporting_routes.py builds for RiskIndicators.credentials.
REPORTING_ROUTES_CREDENTIAL_KEYS = {
    "chromium_logins": 0,
    "chromium_logins_decrypted": 0,
    "chromium_cookies": 0,
    "chromium_cookies_decrypted": 0,
    "dpapi_masterkeys": 0,
    "dpapi_masterkeys_decrypted": 0,
    "titus_findings": 4,
}


def test_source_report_renders_with_reporting_routes_credential_keys():
    """Template must only reference credential keys the report API actually produces."""
    data = _source_report()
    data["risk_indicators"]["credentials"] = dict(REPORTING_ROUTES_CREDENTIAL_KEYS)
    html = render_source_report_html(data)
    assert "Titus Findings" in html
    assert ">4</div>" in html


def test_source_report_fails_loudly_on_missing_credential_key():
    """A missing credential key is a template/data mismatch, not something to render silently."""
    data = _source_report()
    data["risk_indicators"]["credentials"] = {
        k: v for k, v in REPORTING_ROUTES_CREDENTIAL_KEYS.items() if k != "titus_findings"
    }
    with pytest.raises(UndefinedError):
        render_source_report_html(data)
