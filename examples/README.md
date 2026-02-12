# Examples & Synthetic Samples

This directory contains safe, synthetic samples used for testing
`malx-ioc-extractor`. No real malware is included.

## Structure

- `samples/text/` — plain text IOC samples
- `samples/pe/` — synthetic Windows PE files
- `samples/structured/` — logs and structured data
- `samples/safe_test_files/` — EICAR, GTUBE
- `generators/` — scripts to generate reproducible samples

All samples are harmless and suitable for CI pipelines.




🧪 Synthetic Sample Generation Guide

A safe workflow for creating realistic test files without using malware.

This guide explains how to generate harmless, synthetic samples that mimic the structure and IOC patterns found in real-world malicious artifacts. These samples are used for testing malx‑ioc‑extractor safely and reproducibly.
⭐ Why Synthetic Samples?

    Zero risk of infection

    Fully reproducible

    Easy to share in the repo

    Perfect for unit tests and CI

    No legal or ethical complications

Real malware is never required for developing or testing this project.
1. Synthetic PE File Generation

You can generate harmless Windows executables using Python, Go, or .NET.
Below are safe patterns that embed fake IOCs inside the binary.
Option A — Python (PyInstaller)
1. Create a simple Python script:
python

# sample.py
C2_URL = "http://malicious-example.com"
IP = "45.77.12.34"
REG = "HKCU\\Software\\BadActor"
EMAIL = "attacker@example.com"

print("This is a harmless synthetic sample.")

2. Build the executable:
bash

pip install pyinstaller
pyinstaller --onefile sample.py

3. The output file:
Code

dist/sample.exe

This file is completely harmless but contains realistic IOCs for extraction.
Option B — Go (Recommended for clean PE files)
go

package main

import "fmt"

func main() {
    fmt.Println("http://malx-c2.example")
    fmt.Println("192.168.50.10")
    fmt.Println("C:\\Windows\\Temp\\payload.exe")
}

Build it:
bash

GOOS=windows GOARCH=amd64 go build -o sample.exe

Go produces very clean, predictable PE files — great for testing parsers.
2. Synthetic Text Samples

Create .txt files containing mixed IOCs:
Code

http://malx-labs.example
badguy@example.com
45.12.90.33
C:\Users\Public\runme.exe

These are ideal for unit tests.
3. Synthetic Obfuscation Samples

To simulate obfuscation:
Code

hxxp://malx-labs[.]example
45[.]77[.]12[.]34
C2 = "http" + "://" + "evil.example"

These help test your normalisation logic.
4. Public Safe Test Files

You may also use:

    EICAR test file (AV-safe)

    GTUBE (spam filter test)

These are harmless by design.
5. What NOT to Use

❌ Real malware
❌ Password-protected malware archives
❌ Exploit code
❌ Anything requiring execution

If you’re unsure, open an issue before adding a sample.
6. Where to Store Samples

Place synthetic samples under:
Code

examples/samples/

Structure:
Code

examples/
  samples/
    pe/
    text/
    obfuscated/

7. Referencing Samples in Tests

Example:
python

def test_extract_urls_from_pe():
    results = extract_iocs("examples/samples/pe/sample.exe")
    assert "http://malicious-example.com" in results["urls"]

8. Sharing Samples

All synthetic samples must be:

    Harmless

    Non-executable unless intentionally generated

    Fully inspectable in plain text or source form
