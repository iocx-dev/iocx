# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
generate_synthetic_pe.py
Creates a harmless Windows PE file containing embedded fake IOCs.

This script uses Go to produce a clean, predictable PE file.
Requires: Go installed on your system.
"""

import subprocess
import tempfile
from pathlib import Path
import textwrap
import os

env = dict(os.environ)
env["GOOS"] = "windows"
env["GOARCH"] = "amd64"

METADATA = textwrap.dedent("""\
// ---------------------------------------------
// Synthetic Sample Metadata
// Generator: generate_synthetic_pe.py
// Purpose: Embed predictable IOCs for testing
// Type: Go-compiled PE (valid executable)
// IOCs:
//   - http://malx-c2.example
//   - 45.77.12.34
//   - C:\\Windows\\Temp\\payload.exe
//   - attacker@example.com
//   - d41d8cd98f00b204e9800998ecf8427e
// ---------------------------------------------
""")

GO_SOURCE = METADATA + r'''
package main

import "fmt"

func main() {
    fmt.Println("http://malx-c2.example")
    fmt.Println("45.77.12.34")
    fmt.Println("C:\\Windows\\Temp\\payload.exe")
    fmt.Println("attacker@example.com")
    fmt.Println("d41d8cd98f00b204e9800998ecf8427e")
}
'''

def generate_pe(output_path="synthetic_sample.exe"):
    with tempfile.TemporaryDirectory() as tmp:
        go_file = Path(tmp) / "sample.go"
        go_file.write_text(GO_SOURCE)

        cmd = [
            "go", "build",
            "-o", output_path,
            go_file.as_posix()
        ]

        print("[*] Building synthetic PE file...")

        try:
            subprocess.check_call(cmd, env=env)
        except FileNotFoundError:
            print("Error: Go is not installed or not on PATH.")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"Go build failed with exit code {e.returncode}")
            sys.exit(1)

        print(f"[+] Synthetic PE created at: {output_path}")

if __name__ == "__main__":
    import sys
    output = sys.argv[1]
    generate_pe(output)
