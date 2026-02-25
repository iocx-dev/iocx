import argparse
import json
import sys
from ..engine import Engine, EngineConfig
from ..detectors import all_detectors
from .. import __version__


def main():
    parser = argparse.ArgumentParser(
        description="Static IOC extractor for binaries, logs, and text."
    )

    # ---------------------------
    # Argument Groups
    # ---------------------------
    input_group = parser.add_argument_group("Input")
    output_group = parser.add_argument_group("Output")
    engine_group = parser.add_argument_group("Engine Options")
    detector_group = parser.add_argument_group("Detector Options")
    misc_group = parser.add_argument_group("Misc")

    # ---------------------------
    # Input
    # ---------------------------
    input_group.add_argument(
        "input",
        help="File path or raw text. Use '-' to read from stdin."
    )

    # ---------------------------
    # Output
    # ---------------------------
    output_group.add_argument(
        "-o", "--output",
        help="Write JSON output to a file instead of stdout."
    )

    output_group.add_argument(
        "-p", "--pretty",
        action="store_true",
        help="Pretty-print JSON output."
    )

    # ---------------------------
    # Engine Options
    # ---------------------------
    engine_group.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable engine caching."
    )

    # ---------------------------
    # Detector Options
    # ---------------------------
    detector_group.add_argument(
        "--list-detectors",
        action="store_true",
        help="List available detectors and exit."
    )

    # ---------------------------
    # Misc
    # ---------------------------
    misc_group.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit."
    )

    args = parser.parse_args()

    # ---------------------------
    # Handle --version
    # ---------------------------
    if args.version:
        print(__version__)
        return

    # ---------------------------
    # Handle --list-detectors
    # ---------------------------
    if args.list_detectors:
        for name in all_detectors().keys():
            print(name)
        return

    # ---------------------------
    # Configure engine
    # ---------------------------
    config = EngineConfig(
        cache=not args.no_cache,
    )
    engine = Engine(config)

    # ---------------------------
    # Read input
    # ---------------------------
    if args.input == "-":
        data = sys.stdin.read()
    else:
        data = args.input

    result = engine.extract(data)

    # ---------------------------
    # Output
    # ---------------------------
    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2 if args.pretty else None)
    else:
        json.dump(result, sys.stdout, indent=2 if args.pretty else None)
        print()


if __name__ == "__main__":
    main()
