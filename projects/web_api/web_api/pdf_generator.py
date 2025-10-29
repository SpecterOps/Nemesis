"""PDF generation utilities for reports."""

import os
import tempfile
from datetime import datetime
from pathlib import Path

import markdown
import requests
from jinja2 import Environment, FileSystemLoader

DAPR_PORT = os.getenv("DAPR_HTTP_PORT", 3500)
GOTENBERG_URL = f"http://localhost:{DAPR_PORT}/v1.0/invoke/gotenberg/method/forms/chromium/convert/html"

# Initialize Jinja2 environment
templates_dir = Path(__file__).parent / "templates"
jinja_env = Environment(loader=FileSystemLoader(str(templates_dir)))


def render_source_report_html(report_data: dict) -> str:
    """Render source report data to HTML using Jinja2 template."""
    template = jinja_env.get_template("source_report.html")

    # Format the generated_at timestamp
    generated_at = report_data.get("generated_at")
    if isinstance(generated_at, datetime):
        generated_at = generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")

    # Prepare AI synthesis with markdown converted to HTML
    ai_synthesis = report_data.get("ai_synthesis")
    # print(f"DEBUG pdf_generator: ai_synthesis={ai_synthesis}")
    if ai_synthesis and ai_synthesis.get("report_markdown"):
        # print(f"DEBUG pdf_generator: Converting markdown to HTML, length={len(ai_synthesis['report_markdown'])}")
        # Convert markdown to HTML
        html_content = markdown.markdown(ai_synthesis["report_markdown"], extensions=["extra", "nl2br", "sane_lists"])
        # print(f"DEBUG pdf_generator: HTML length={len(html_content)}")
        ai_synthesis = {
            "risk_level": ai_synthesis.get("risk_level"),
            "report_html": html_content,
        }
    # else:
    #     print(f"DEBUG pdf_generator: No markdown found in ai_synthesis")

    # Prepare data for template
    context = {
        "source": report_data.get("source", "Unknown"),
        "generated_at": generated_at,
        "summary": report_data.get("summary", {}),
        "risk_indicators": report_data.get("risk_indicators", {}),
        "findings_detail": report_data.get("findings_detail", {}),
        "top_findings": report_data.get("top_findings", []),
        "enrichment_performance": report_data.get("enrichment_performance", {}),
        "ai_synthesis": ai_synthesis,  # Optional AI synthesis with HTML
    }

    return template.render(**context)


def render_system_report_html(report_data: dict) -> str:
    """Render system report data to HTML using Jinja2 template."""
    template = jinja_env.get_template("system_report.html")

    # Format the generated_at timestamp
    generated_at = report_data.get("generated_at")
    if isinstance(generated_at, datetime):
        generated_at = generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")

    # Prepare data for template
    context = {
        "generated_at": generated_at,
        "summary": report_data.get("summary", {}),
        "findings_by_category": report_data.get("findings_by_category", {}),
        "findings_by_severity": report_data.get("findings_by_severity", {}),
        "sources": report_data.get("sources", []),
    }

    return template.render(**context)


def convert_html_to_pdf(html_content: str) -> bytes:
    """
    Convert HTML content to PDF using Gotenberg via Dapr.

    Args:
        html_content: HTML string to convert

    Returns:
        PDF file contents as bytes

    Raises:
        Exception: If PDF conversion fails
    """
    # Create a temporary file for the HTML
    with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False, encoding="utf-8") as temp_html:
        temp_html.write(html_content)
        temp_html_path = temp_html.name

    try:
        # Read the HTML file and prepare for Gotenberg
        with open(temp_html_path, "rb") as f:
            # Gotenberg Chromium options for better rendering
            data = {
                "marginTop": "0.4",
                "marginBottom": "0.4",
                "marginLeft": "0.4",
                "marginRight": "0.4",
                "preferCssPageSize": "true",
                "printBackground": "true",
                "scale": "1.0",
            }

            # Files must be sent with the file content
            files = {"index.html": ("index.html", f, "text/html")}

            # Call Gotenberg via Dapr
            response = requests.post(GOTENBERG_URL, files=files, data=data, timeout=60)

            if response.status_code == 200:
                return response.content
            else:
                raise Exception(f"Gotenberg returned status {response.status_code}: {response.text}")

    finally:
        # Clean up temporary file
        try:
            os.unlink(temp_html_path)
        except Exception:
            pass


def generate_source_report_pdf(report_data: dict) -> bytes:
    """
    Generate a PDF for a source report.

    Args:
        report_data: Source report data dictionary

    Returns:
        PDF file contents as bytes
    """
    html_content = render_source_report_html(report_data)
    return convert_html_to_pdf(html_content)


def generate_system_report_pdf(report_data: dict) -> bytes:
    """
    Generate a PDF for a system-wide report.

    Args:
        report_data: System report data dictionary

    Returns:
        PDF file contents as bytes
    """
    html_content = render_system_report_html(report_data)
    return convert_html_to_pdf(html_content)
