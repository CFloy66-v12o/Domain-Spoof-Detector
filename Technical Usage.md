## Technical Usage

This section is intended for security analysts, system administrators, developers, researchers, and other users comfortable with command-line tools and structured output.

### Clone the Repository

Clone the repository over HTTPS:

```bash
git clone https://github.com/YOUR-USERNAME/domain-spoof-detector.git
cd domain-spoof-detector
```

Confirm that the Python program and Unicode dataset are present:

```bash
ls -l idnHomoglyphDetector.py confusables.txt
```

In PowerShell:

```powershell
Get-Item .\idnHomoglyphDetector.py, .\confusables.txt
```

### Python Requirements

The program requires Python 3.10 or later because it uses modern type-hint syntax such as:

```python
str | None
list[str]
dict[str, str]
```

Check the installed version:

```bash
python3 --version
```

On Windows:

```powershell
py --version
```

The application currently uses only Python standard-library modules, so no external packages need to be installed.

An isolated virtual environment is optional but recommended for consistent development:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Command Syntax

```text
python3 idnHomoglyphDetector.py VALUE [--trusted DOMAIN]... [--json]
```

Arguments:

| Argument           | Purpose                                                                  |
| ------------------ | ------------------------------------------------------------------------ |
| `VALUE`            | Required URL, hostname, IDN, Punycode hostname, or IP address to analyze |
| `--trusted DOMAIN` | Optional legitimate domain used as an impersonation baseline             |
| `--json`           | Returns structured JSON instead of the human-readable report             |
| `-h`, `--help`     | Displays command help and exits                                          |

`--trusted` uses the `append` action in `argparse`, so it can be repeated to supply multiple trusted domains.

### Basic Analysis

Analyze a hostname without a comparison target:

```bash
python3 idnHomoglyphDetector.py example.com
```

Analyze a complete URL:

```bash
python3 idnHomoglyphDetector.py \
    "https://example.com/account/login?source=email"
```

The URL is parsed locally with `urllib.parse.urlsplit()`. Only the extracted hostname is analyzed; no network request is generated.

### Trusted-Domain Comparison

Compare a suspected domain with a legitimate domain:

```bash
python3 idnHomoglyphDetector.py \
    "paypa1.example" \
    --trusted "paypal.example"
```

Compare one suspected domain against multiple protected domains:

```bash
python3 idnHomoglyphDetector.py \
    "suspicious.example" \
    --trusted "paypal.example" \
    --trusted "apple.example" \
    --trusted "microsoft.example"
```

PowerShell equivalent:

```powershell
py .\idnHomoglyphDetector.py "suspicious.example" `
    --trusted "paypal.example" `
    --trusted "apple.example" `
    --trusted "microsoft.example"
```

Trusted-domain comparison enables the detection of contextual similarities that would be inappropriate to flag globally, including:

* ASCII digit-to-letter substitutions
* Character insertion or omission
* Adjacent-character transposition
* Hyphen manipulation
* Multi-character visual substitutions
* Unicode skeleton matches

### Unicode Homoglyph Analysis

Analyze a mixed Latin/Cyrillic hostname:

```bash
python3 idnHomoglyphDetector.py \
    "pаypal.example" \
    --trusted "paypal.example"
```

The first `а` in the suspected hostname above is Cyrillic `U+0430`, not ASCII Latin `U+0061`.

The report includes character-level evidence such as:

```text
index 1: 'а' = U+0430
CYRILLIC SMALL LETTER A
script=Cyrillic
resembles ASCII 'a'
```

### Punycode Analysis

Analyze a DNS-compatible IDN representation:

```bash
python3 idnHomoglyphDetector.py \
    "xn--80ak6aa92e.example" \
    --trusted "apple.example"
```

The detector:

1. Recognizes the `xn--` label.
2. Decodes the label using Python’s IDNA codec.
3. Identifies its writing systems.
4. generates character-level evidence.
5. Computes a Unicode confusable skeleton.
6. Compares that skeleton with the trusted domain.

### JSON Output

Return a machine-readable report:

```bash
python3 idnHomoglyphDetector.py \
    "paypa1.example" \
    --trusted "paypal.example" \
    --json
```

Redirect the output to a file:

```bash
python3 idnHomoglyphDetector.py \
    "paypa1.example" \
    --trusted "paypal.example" \
    --json > report.json
```

PowerShell:

```powershell
py .\idnHomoglyphDetector.py "paypa1.example" `
    --trusted "paypal.example" `
    --json |
    Set-Content -Encoding utf8 .\report.json
```

Because character evidence may contain Unicode, use UTF-8 when storing or transmitting the output.

### Process JSON with `jq`

Extract the overall result:

```bash
python3 idnHomoglyphDetector.py \
    "paypa1.example" \
    --trusted "paypal.example" \
    --json |
    jq '{hostname, risk_score, verdict}'
```

Display only individual findings:

```bash
python3 idnHomoglyphDetector.py \
    "paypa1.example" \
    --trusted "paypal.example" \
    --json |
    jq '.findings[]'
```

Display critical findings:

```bash
python3 idnHomoglyphDetector.py \
    "paypa1.example" \
    --trusted "paypal.example" \
    --json |
    jq '.findings[] | select(.severity == "critical")'
```

### Process JSON with PowerShell

Store the report as a PowerShell object:

```powershell
$report = py .\idnHomoglyphDetector.py "paypa1.example" `
    --trusted "paypal.example" `
    --json |
    ConvertFrom-Json
```

Display selected properties:

```powershell
$report |
    Select-Object hostname, risk_score, verdict
```

Display high and critical findings:

```powershell
$report.findings |
    Where-Object severity -in @("high", "critical")
```

Display character evidence:

```powershell
$report.character_details |
    Format-Table index, character, code_point, unicode_name, script, looks_like
```

### Use as a Python Module

The analysis function can be imported into another Python program:

```python
from idnHomoglyphDetector import analyze

report = analyze(
    "paypa1.example",
    trusted_domains=["paypal.example"],
)

print(report.hostname)
print(report.risk_score)
print(report.verdict)

for finding in report.findings:
    print(
        finding.severity,
        finding.reason,
        finding.detail,
    )
```

Convert the dataclass report to a dictionary:

```python
from dataclasses import asdict

from idnHomoglyphDetector import analyze

report = analyze(
    "pаypal.example",
    trusted_domains=["paypal.example"],
)

report_data = asdict(report)
```

Serialize it as JSON:

```python
import json
from dataclasses import asdict

from idnHomoglyphDetector import analyze

report = analyze(
    "pаypal.example",
    trusted_domains=["paypal.example"],
)

print(
    json.dumps(
        asdict(report),
        indent=2,
        ensure_ascii=False,
    )
)
```

Importing the module does not execute the command-line interface because `main()` is protected by:

```python
if __name__ == "__main__":
    main()
```

The Unicode data is loaded when the module is imported, so `confusables.txt` must remain available beside `idnHomoglyphDetector.py`.

### Verify the Unicode Dataset

Confirm that the loader can find and parse the dataset:

```bash
python3 -c "import idnHomoglyphDetector as d; print(d.CONFUSABLES_VERSION); print(len(d.UNICODE_CONFUSABLES))"
```

For the included dataset, the expected result is:

```text
17.0.0
6565
```

A different mapping count may indicate that the dataset was changed, truncated, or replaced with another Unicode version.

### Suggested Validation Cases

Legitimate ASCII domain:

```bash
python3 idnHomoglyphDetector.py \
    "paypal.example" \
    --trusted "paypal.example"
```

ASCII look-alike substitution:

```bash
python3 idnHomoglyphDetector.py \
    "paypa1.example" \
    --trusted "paypal.example"
```

Character omission:

```bash
python3 idnHomoglyphDetector.py \
    "paypa.example" \
    --trusted "paypal.example"
```

Adjacent transposition:

```bash
python3 idnHomoglyphDetector.py \
    "payapl.example" \
    --trusted "paypal.example"
```

Hyphen manipulation:

```bash
python3 idnHomoglyphDetector.py \
    "pay-pal.example" \
    --trusted "paypal.example"
```

Mixed-script homoglyph:

```bash
python3 idnHomoglyphDetector.py \
    "pаypal.example" \
    --trusted "paypal.example"
```

Punycode input:

```bash
python3 idnHomoglyphDetector.py \
    "xn--80ak6aa92e.example" \
    --trusted "apple.example"
```

IP address:

```bash
python3 idnHomoglyphDetector.py "192.0.2.10"
```

The `.example` top-level domain is reserved for documentation and testing, making it preferable for examples that should not refer to real websites.

### Operational Considerations

The detector performs static string analysis. It does not currently:

* Resolve the domain through DNS
* Query WHOIS or RDAP records
* Retrieve registration dates
* Inspect TLS certificates
* Query threat-intelligence or reputation services
* Connect to the supplied host
* Follow redirects
* Retrieve webpage content
* Accept multiple investigation targets in a single execution
* Assign a risk-based process exit code

Because risk findings do not currently affect the process exit status, automation should inspect the JSON `verdict`, `risk_score`, or `findings` fields rather than relying on `$?` or the shell exit code.

The tool should be treated as one enrichment source in a broader investigation. A similarity finding indicates that analyst review is warranted; it does not independently establish malicious intent.
