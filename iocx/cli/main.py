import argparse
import json
import sys
from ..engine import Engine, EngineConfig
from ..detectors import all_detectors

def main():
    parser = argparse.ArgumentParser(
        description="Static IOC extractor for binaries, logs, and text."
    )

    parser.add_argument(
        "input",
        help="File path or raw text. The engine will auto-detect file type."
    )

    args = parser.parse_args()

    # Configure engine
    config = EngineConfig()
    engine = Engine(config)

    if args.input == "-":
       data = sys.stdin.read()
    else:
       data = args.input

    result = engine.extract(data)

    # Print JSON output
    json.dump(result, sys.stdout, indent=2)
    print()

if __name__ == "__main__":
    main()
