## Quick Start for Everyday Users

This tool checks whether a web address contains characters or spelling changes that may make it look like another domain. It performs the analysis locally and does **not** open the website, visit the address, or send information to it.

### What You Need

Before using the tool, you need:

1. Python 3.10 or newer installed on your computer.
2. This project downloaded and extracted into a folder.
3. Both of these files in the same folder:

```text
idnHomoglyphDetector.py
confusables.txt
```

Python can be downloaded from:

https://www.python.org/downloads/

On Windows, select the option to **Add Python to PATH** during installation if it is offered.

### Download the Project

1. Open this GitHub repository.
2. Select the green **Code** button.
3. Select **Download ZIP**.
4. Open your Downloads folder.
5. Right-click the downloaded ZIP file and select **Extract All**.
6. Open the extracted project folder.

You do not need to install Git or understand programming to use the downloaded tool.

### Open PowerShell in the Project Folder

On Windows:

1. Open the folder containing `idnHomoglyphDetector.py`.
2. Click the File Explorer address bar at the top.
3. Type:

```text
powershell
```

4. Press Enter.

PowerShell should open directly in the project folder.

### Confirm That Python Is Available

Enter:

```powershell
py --version
```

If that does not work, try:

```powershell
python --version
```

A successful result should display a Python version, such as:

```text
Python 3.14.0
```

### Check a Domain

To examine a domain without comparing it to a known legitimate domain, enter:

```powershell
py .\idnHomoglyphDetector.py "example.com"
```

If `py` does not work but `python` does, use:

```powershell
python .\idnHomoglyphDetector.py "example.com"
```

On macOS or Linux, use:

```bash
python3 ./idnHomoglyphDetector.py "example.com"
```

### Compare a Suspicious Domain with the Real Domain

For the most useful analysis, provide both:

* The suspicious domain you received
* The legitimate domain you expected

Use this format:

```powershell
py .\idnHomoglyphDetector.py "SUSPICIOUS-DOMAIN" --trusted "REAL-DOMAIN"
```

For example:

```powershell
py .\idnHomoglyphDetector.py "paypa1.example" --trusted "paypal.example"
```

In this example, the suspicious domain uses the number `1` where a lowercase `l` would normally appear.

### Check a Complete Link

You can paste a complete URL:

```powershell
py .\idnHomoglyphDetector.py "https://paypa1.example/account/login" --trusted "paypal.example"
```

The tool extracts and examines the hostname. It does not open the page.

Always put the URL inside quotation marks. This prevents characters such as `&` from being interpreted as PowerShell commands.

### Check an Internationalized Domain

Some deceptive domains use letters from another writing system that resemble familiar English letters.

For example, the following suspicious hostname contains a Cyrillic `а` even though it resembles a Latin `a`:

```powershell
py .\idnHomoglyphDetector.py "pаypal.example" --trusted "paypal.example"
```

The tool may display evidence similar to:

```text
'а' = U+0430
CYRILLIC SMALL LETTER A
resembles ASCII 'a'
```

This shows that the character is not the ordinary Latin `a`.

### Check a Punycode Domain

A domain beginning with `xn--` is represented in Punycode. Punycode is not automatically malicious, but it can represent Unicode characters that deserve examination.

Example:

```powershell
py .\idnHomoglyphDetector.py "xn--80ak6aa92e.example" --trusted "apple.example"
```

The tool will decode the hostname and display information about its underlying characters.

### Understanding the Result

The report displays a risk score and one of these general results:

* **Low risk:** The implemented checks did not identify a strong warning sign.
* **Suspicious:** The domain contains characteristics that deserve closer examination.
* **High risk:** The tool found strong similarities to a trusted domain or other significant impersonation indicators.

The report may also explain that it found:

* Unicode characters
* Punycode
* Different writing systems within one domain label
* Characters that visually resemble other characters
* Missing or additional characters
* Reversed neighboring characters
* Added or removed hyphens
* Strong similarity to a trusted domain

### Important Safety Guidance

Do not open a suspicious link merely to copy it.

If possible, obtain the address by:

* Right-clicking the link and selecting **Copy link address**
* Copying the visible link from an email or message
* Using a defanged address supplied by a security analyst

The tool only analyzes text. It does not confirm that a website is safe, and its findings do not prove that a domain is malicious.

Even if the result says **low risk**, continue to use caution when:

* The message was unexpected
* The sender requests a password or verification code
* The link leads to a login page
* The message creates urgency or threatens consequences
* The sender requests payment or personal information

When in doubt, navigate to the organization’s official website independently instead of using the received link.

### Optional JSON Output

Most everyday users do not need JSON output. It is intended for analysts or other programs.

To request it, add `--json`:

```powershell
py .\idnHomoglyphDetector.py "paypa1.example" --trusted "paypal.example" --json
```

### Common Problems

#### “Python was not found”

Python may not be installed or may not have been added to the system path. Install Python from:

https://www.python.org/downloads/

Then close and reopen PowerShell.

#### “The following arguments are required: value”

The command was entered without a domain to investigate. Include the suspected domain after the script name:

```powershell
py .\idnHomoglyphDetector.py "example.com"
```

#### “No such file” or “cannot open file”

PowerShell is probably not open in the project folder. Confirm that the folder contains:

```text
idnHomoglyphDetector.py
confusables.txt
```

Then open PowerShell from that folder and try again.

#### The confusables file cannot be found

Confirm that its filename is exactly:

```text
confusables.txt
```

It must be in the same folder as `idnHomoglyphDetector.py`. Make sure Windows did not rename it to:

```text
confusables.txt.txt
```

You can enable **File name extensions** under the **View** menu in File Explorer to inspect the complete filename.
