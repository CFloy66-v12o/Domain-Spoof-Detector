# Web deployment

This repository includes a Flask interface for the Domain Spoof Detector.
The original command-line interface remains available.

## Required Unicode dataset

For full Unicode coverage, download Unicode 17.0.0 `confusables.txt` from:

https://www.unicode.org/Public/17.0.0/security/confusables.txt

Place the file beside `idnHomoglyphDetector.py` before deployment. If it is
missing, the application starts with the smaller built-in Greek/Cyrillic map
and identifies that reduced dataset in the page footer and `/health` result.

## Run locally

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests
python app.py
```

Open `http://127.0.0.1:8080`.

## Deploy to Google Cloud Run

From the project directory, after installing and authenticating the Google
Cloud CLI:

```powershell
gcloud run deploy fdf-domain-checker `
  --source . `
  --region us-east1 `
  --allow-unauthenticated `
  --min 0 `
  --max 3
```

Cloud Run will return a public HTTPS service URL. Test both `/` and `/health`.

## Google Sites

Use the Cloud Run HTTPS URL as the destination of the Google Sites button
named **Use Web-Based Tool**, or use **Insert > Embed > URL** to place the
checker directly on a page.

The application sends a `Content-Security-Policy` that permits framing by
Google Sites and the Frederick Data Forensics domain. If the final published
site uses a different hostname, add that exact HTTPS origin to the
`frame-ancestors` directive in `app.py` and redeploy.

## Privacy behavior

- The application submits inputs using POST rather than query parameters.
- It does not perform DNS, RDAP, WHOIS, TLS, reputation, or webpage requests.
- It reflects only the extracted hostname, not a submitted URL path, query,
  fragment, embedded credentials, or private token.
- It applies `no-store`, `no-referrer`, content-type, permissions, and CSP
  response headers.
- Application code does not intentionally log form bodies. Hosting platforms
  may retain ordinary request metadata according to their own logging policy.

## Before public launch

1. Add the full Unicode `confusables.txt` dataset.
2. Run the automated tests.
3. Confirm `/health` reports Unicode version 17.0.0.
4. Test Unicode, Punycode, ASCII typosquatting, malformed, and long inputs.
5. Confirm Google Sites can embed the final service URL.
6. Add rate limiting or an edge protection service before advertising widely.
7. Keep the heuristic/not-a-safety-verdict language visible.
