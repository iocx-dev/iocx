"""
generate_obfuscated_pe.py
Creates a harmless Windows PE file containing embedded fake IOCs.

Pure Python version — no Go required.
Produces a valid PE stub with IOCs stored in the .rdata section.
"""

import sys
from pathlib import Path

# Ensure project root is importable
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

# Reuse the same minimal PE stub definition from examples.generators.python.generate_synthetic_pe
from examples.generators.python.generate_synthetic_pe import MINIMAL_PE_STUB

# IOC payload we want to embed for testing
IOC_PAYLOAD = b"\n".join(
    [
        b"hxxp://malx-labs[.]example",
        b"45[.]77[.]12[.]34",
        b"C2 = 'htt' + 'p://evil.example'",
    ]
)

def generate_pe(output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Pad the stub to the start of the .rdata raw data (0x200)
    stub = MINIMAL_PE_STUB
    if len(stub) > 0x200:
        raise ValueError("Stub is larger than expected; adjust layout.")
    padding = b"\x00" * (0x200 - len(stub))

    with path.open("wb") as f:
        f.write(stub)
        f.write(padding)
        f.write(IOC_PAYLOAD)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} OUTPUT_PATH", file=sys.stderr)
        sys.exit(1)

    generate_pe(sys.argv[1])
    print(f"[+] Obfuscated PE created at: {sys.argv[1]}")
