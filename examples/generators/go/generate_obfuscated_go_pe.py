"""
generate_obfuscated_pe.py
Creates a harmless Windows PE file with obfuscated IOCs for testing deobfuscation logic.

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

# Metadata block embedded directly into the generated Go source
METADATA = textwrap.dedent("""\
// ---------------------------------------------
// Synthetic Sample Metadata
// Generator: generate_obfuscated_pe.py
// Purpose: Test IOC deobfuscation logic
// Type: Go-compiled PE (valid executable)
// IOCs (obfuscated):
//   - hxxp://malx-labs[.]example
//   - 45[.]77[.]12[.]34
//   - C2 = "htt" + "p://" + "evil.example"
// ---------------------------------------------
""")

GO_SOURCE = METADATA + r'''
package main

import "fmt"

func main() {
    fmt.Println("hxxp://malx-labs[.]example")
    fmt.Println("45[.]77[.]12[.]34")
    fmt.Println("C2 = \"htt\" + \"p://\" + \"evil.example\"")
}
'''

def generate_pe(output_path="synthetic_obfuscated.exe"):
    with tempfile.TemporaryDirectory() as tmp:
        go_file = Path(tmp) / "sample.go"
        go_file.write_text(GO_SOURCE)

        cmd = ["go", "build", "-o", output_path, go_file.as_posix()]

        print("[*] Building obfuscated synthetic PE file...")

        try:
            subprocess.check_call(cmd, env=env)
        except FileNotFoundError:
            print("Error: Go is not installed or not on PATH.")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"Go build failed with exit code {e.returncode}")
            sys.exit(1)

        print(f"[+] Obfuscated PE created at: {output_path}")

if __name__ == "__main__":
    import sys
    output = sys.argv[1]
    generate_pe(output)
