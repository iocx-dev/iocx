"""
generate_synthetic_pe.py
Creates a harmless Windows PE file containing embedded fake IOCs.

Pure Python version — no Go required.
Produces a valid PE stub with IOCs stored in the .rdata section.
"""

import sys
from pathlib import Path

MINIMAL_PE_STUB = (
    b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * (0x80 - 0x40) +
    b"PE\x00\x00" +
    b"\x4C\x01" + b"\x01\x00" + b"\x00" * 12 + b"\xE0\x00" + b"\x02\x02" +
    b"\x0B\x01" + b"\x08\x00" + b"\x00" * 28 +
    b"\x00\x10\x00\x00" + b"\x00\x10\x00\x00" +
    b"\x00" * 16 +
    b"\x00\x02\x00\x00" + b"\x00" * 4 +
    b"\x03\x00" + b"\x00\x00" +
    b"\x00\x10\x00\x00" + b"\x00\x10\x00\x00" +
    b"\x00\x10\x00\x00" + b"\x00\x10\x00\x00" +
    b"\x00" * 8 +
    b"\x10\x00\x00\x00" +
    b"\x00" * (16 * 8) +
    b".rdata\x00\x00" +
    b"\x00\x10\x00\x00" + b"\x00\x20\x00\x00" +
    b"\x00\x10\x00\x00" + b"\x00\x02\x00\x00" +
    b"\x00" * 8 + b"\x00\x00" + b"\x00\x00" +
    b"\x40\x00\x00\x40"
)

IOC_PAYLOAD = b"\n".join(
    [
        b"http://malx-c2.example",
        b"45.77.12.34",
        b"C:\\Windows\\Temp\\payload.exe",
        b"attacker@example.com",
        b"d41d8cd98f00b204e9800998ecf8427e",
    ]
)

def generate_pe(output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    stub = MINIMAL_PE_STUB
    if len(stub) > 0x200:
        raise ValueError("PE stub is larger than expected; adjust layout.")

    padding = b"\x00" * (0x200 - len(stub))

    with path.open("wb") as f:
        f.write(stub)
        f.write(padding)
        f.write(IOC_PAYLOAD)

    print(f"[+] Synthetic PE created at: {output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} OUTPUT_PATH", file=sys.stderr)
        sys.exit(1)

    generate_pe(sys.argv[1])
