from __future__ import annotations

import os
from dataclasses import asdict

from flask import Flask, render_template, request

from idnHomoglyphDetector import (
    CONFUSABLES_VERSION,
    analyze,
    normalize_trusted_domain,
)


MAX_INPUT_LENGTH = 2048
MAX_TRUSTED_LENGTH = 253


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "form-action 'self'; "
            "base-uri 'none'; "
            "object-src 'none'; "
            "frame-ancestors https://sites.google.com "
            "https://*.googleusercontent.com "
            "https://frederickdataforensics.net "
            "https://www.frederickdataforensics.net"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            report=None,
            error=None,
            submitted_value="",
            trusted_value="",
            confusables_version=CONFUSABLES_VERSION,
        )

    @app.post("/analyze")
    def analyze_submission():
        value = request.form.get("value", "").strip()
        trusted = request.form.get("trusted", "").strip()
        acknowledged = request.form.get("acknowledged") == "yes"
        error = None
        report_data = None
        display_value = ""
        display_trusted = ""

        if not acknowledged:
            error = "Please acknowledge the tool's limitations before analyzing."
        elif not value:
            error = "Enter a domain or link to analyze."
        elif len(value) > MAX_INPUT_LENGTH:
            error = "The submitted value is too long. Enter a domain or ordinary link."
        elif len(trusted) > MAX_TRUSTED_LENGTH:
            error = "The trusted comparison domain is too long."
        else:
            try:
                trusted_domains = [trusted] if trusted else []
                report = analyze(value, trusted_domains)
                report_data = asdict(report)

                display_trusted = (
                    normalize_trusted_domain(trusted) if trusted else ""
                )

                # Do not reflect a full URL that may contain a private path,
                # query string, fragment, or embedded credentials.
                report_data["input_value"] = report.hostname
                report_data["comparison_domain"] = display_trusted
                report_data["display_verdict"] = {
                    "low risk": (
                        "No supported domain-name indicators detected"
                    ),
                    "suspicious": (
                        "Supported domain-name indicators detected"
                    ),
                    "high risk": (
                        "Strong domain-name impersonation indicators detected"
                    ),
                }.get(report.verdict, report.verdict)

                display_value = report.hostname
            except (UnicodeError, ValueError) as exc:
                error = f"The hostname could not be analyzed: {exc}"

        return render_template(
            "index.html",
            report=report_data,
            error=error,
            submitted_value=display_value,
            trusted_value=display_trusted,
            confusables_version=CONFUSABLES_VERSION,
        ), 400 if error else 200

    @app.get("/health")
    def health():
        return {"status": "ok", "confusables_version": CONFUSABLES_VERSION}

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
