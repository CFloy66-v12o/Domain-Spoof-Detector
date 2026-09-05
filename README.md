
A Python command-line tool that detects IDN homograph attacks, Unicode confusables, mixed-script domains, and ASCII typosquatting through code-point analysis and trusted-domain comparison.
# Domain Spoof Detector

Domain Spoof Detector is a Python command-line tool designed to identify potential domain-impersonation techniques used in phishing, credential theft, social engineering, and other malicious activity. It analyzes a URL or hostname without connecting to it and reports characteristics that may indicate an Internationalized Domain Name (IDN) homograph attack, Unicode homoglyph attack, or ASCII-based typosquatting attempt.

The tool examines the actual characters underlying a hostname rather than relying only on how the domain appears visually. For non-ASCII and other notable characters, it can report the character’s position, Unicode code point, official Unicode name, writing system, and corresponding visual skeleton. This makes it possible to distinguish visually similar characters such as the ASCII Latin `a` (`U+0061`) and Cyrillic `а` (`U+0430`).

## Features

* Extracts hostnames from plain domain names and complete URLs
* Performs analysis without visiting or connecting to the supplied address
* Detects Punycode labels beginning with `xn--`
* Converts between Unicode and ASCII/Punycode hostname representations
* Identifies non-ASCII characters within domain names
* Examines the Unicode code point and official name of notable characters
* Detects multiple writing systems used within the same domain label
* Builds visual skeletons using the Unicode Consortium’s confusables dataset
* Compares suspicious domains against explicitly supplied trusted domains
* Detects common ASCII look-alike substitutions, such as `1` for `l` and `0` for `o`
* Detects multi-character look-alikes, such as `rn` resembling `m`
* Detects adjacent-character transpositions
* Detects character insertions and omissions using Levenshtein distance
* Detects hyphen insertion or removal
* Assigns a heuristic risk score and overall verdict
* Supports human-readable and JSON-formatted output
* Supports comparison against multiple trusted domains

## Detection Categories

### IDN and Punycode Detection

Internationalized Domain Names allow Unicode characters to appear in domain names. Their DNS-compatible representation uses Punycode and commonly begins with the `xn--` prefix.

The presence of Punycode is not inherently malicious. Many legitimate websites use internationalized domain names. However, Punycode can conceal characters that resemble letters in a trusted domain, so the tool decodes these labels for further examination.

### Unicode Homoglyph Detection

A homoglyph is a character that visually resembles another character. Attackers can combine characters from different writing systems to create a domain that appears legitimate to a human reader.

For example:

```text
paypal.com
pаypal.com
```

These domains appear similar, but the second domain contains a Cyrillic `а`:

```text
ASCII a:    U+0061 LATIN SMALL LETTER A
Cyrillic а: U+0430 CYRILLIC SMALL LETTER A
```

Domain Spoof Detector exposes this underlying character information and compares the domain’s visual skeleton against trusted domains.

### Mixed-Script Detection

The program identifies domain labels containing characters from multiple writing systems. For example, a single label containing both Latin and Cyrillic letters may warrant further investigation.

Mixed-script analysis is performed at the individual label level. This avoids automatically treating a domain as mixed-script merely because its internationalized name uses a Latin top-level domain such as `.com`.

### ASCII Typosquatting Detection

Domain impersonation does not require Unicode. Attackers can register ASCII-only domains that exploit common typing mistakes or visual similarities.

The tool checks trusted-domain comparisons for techniques including:

* Character substitution: `paypa1.com` versus `paypal.com`
* Character omission: `paypa.com`
* Character insertion: `paypall.com`
* Adjacent transposition: `payapl.com`
* Hyphen manipulation: `pay-pal.com`
* Sequence substitution: `rn` resembling `m`

These checks require at least one trusted domain because digits, hyphens, and similar spellings are not inherently suspicious without a meaningful comparison target.

## Unicode Confusables Data

The detector uses the Unicode Consortium’s `confusables.txt` dataset to create visual skeletons for comparison. The included dataset is based on Unicode 17.0.0 and contains thousands of mappings between visually confusable characters.

Unicode Technical Standard #39 defines mechanisms for detecting potential security problems involving Unicode identifiers:

* https://www.unicode.org/reports/tr39/
* https://www.unicode.org/Public/17.0.0/security/confusables.txt

The project uses this dataset as one component of its detection logic. It should not be interpreted as a claim of complete conformance with every requirement of Unicode Technical Standard #39.

## Requirements

* Python 3.10 or later
* `confusables.txt` located in the same directory as the Python script

The program uses Python’s standard library and does not require additional third-party Python packages.

## Repository Structure

```text
domain-spoof-detector/
├── idnHomoglyphDetector.py
├── confusables.txt
├── README.md
├── LICENSE
└── THIRD_PARTY_NOTICES.md
```

## Usage

General syntax:

```text
python3 idnHomoglyphDetector.py VALUE [--trusted DOMAIN] [--json]
```

Display help:

```powershell
python3 .\idnHomoglyphDetector.py --help
```

Analyze a hostname:

```powershell
python3 .\idnHomoglyphDetector.py example.com
```

Compare a suspected typosquatting domain with a trusted domain:

```powershell
python3 .\idnHomoglyphDetector.py paypa1.com --trusted paypal.com
```

Analyze a Punycode hostname:

```powershell
python3 .\idnHomoglyphDetector.py xn--80ak6aa92e.com --trusted apple.com
```

Analyze a Unicode hostname:

```powershell
python3 .\idnHomoglyphDetector.py "pаypal.com" --trusted paypal.com
```

Request JSON output:

```powershell
python3 .\idnHomoglyphDetector.py paypa1.com --trusted paypal.com --json
```

Save JSON output to a file:

```powershell
python3 .\idnHomoglyphDetector.py paypa1.com --trusted paypal.com --json > results.json
```

Compare against multiple trusted domains:

```powershell
python3 .\idnHomoglyphDetector.py suspicious-domain.com `
    --trusted paypal.com `
    --trusted apple.com `
    --trusted microsoft.com
```

## Understanding the Results

The report may include:

* Original extracted hostname
* Decoded Unicode representation
* ASCII/Punycode representation
* Writing systems detected
* Computed visual skeleton
* Character-level Unicode evidence
* Individual findings and severity levels
* Numerical risk score
* Overall verdict

The verdicts are heuristic:

* **Low risk:** No significant indicators were identified by the implemented checks.
* **Suspicious:** One or more characteristics warrant additional investigation.
* **High risk:** Strong visual similarity or trusted-domain impersonation indicators were detected.

A low-risk result does not establish that a domain is safe. Likewise, a high-risk result does not independently prove malicious ownership or intent.

## Intended Use

This project is intended for:

* Cybersecurity education
* Digital-forensics and incident-response training
* Phishing triage
* Suspicious-link analysis
* Domain-brand monitoring
* Security research
* Demonstrating Unicode and IDN security concepts

The detector performs static string analysis only. It does not conduct DNS resolution, WHOIS or RDAP queries, certificate inspection, reputation checks, webpage retrieval, or malware analysis.

## Limitations

* Detection is heuristic and may produce false positives or false negatives.
* Legitimate internationalized domains may contain Unicode or multiple scripts.
* Visual similarity depends partly on the font and rendering environment.
* Trusted-domain comparison is only as complete as the trusted domains supplied by the user.
* Levenshtein distance identifies textual similarity but does not prove impersonation.
* The Unicode confusables dataset may change between Unicode versions.
* The tool does not determine domain ownership, registration intent, reputation, or malicious activity.
* The tool does not replace browser protections, threat-intelligence services, or analyst review.
* Unicode script detection in this project is simplified and does not implement the complete Unicode Script_Extensions algorithm.
* The current tool analyzes one investigation target per execution.

## Security and Privacy

The tool does not navigate to, retrieve content from, or otherwise contact the supplied hostname. Analysis is performed locally on the input string and the locally stored Unicode confusables dataset.

Users should still avoid opening suspicious URLs in a normal browser or resolving potentially malicious domains from sensitive systems.

## Future Development

Possible future improvements include:

* Batch analysis from text, CSV, or JSON files
* Pipeline input through standard input
* Trusted-domain lists loaded from files
* RDAP and domain-registration analysis
* DNS and certificate inspection
* Domain-age and reputation checks
* Public-suffix-aware domain comparison
* Expanded script-property analysis
* Exportable HTML or CSV reports
* Automated unit tests
* SIEM or SOAR integration
* Configurable scoring policies

## License

The Python source code is licensed under the MIT License. See `LICENSE`.

The included Unicode confusables dataset is provided by Unicode, Inc. under the Unicode License v3. See `THIRD_PARTY_NOTICES.md` and the licensing information contained in `confusables.txt`.

## Disclaimer

This software is provided for educational, defensive-security, and research purposes. Its findings should be treated as indicators requiring analyst interpretation, not as conclusive determinations that a domain is safe or malicious.
