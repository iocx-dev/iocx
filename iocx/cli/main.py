import argparse
import json
import sys
from ..engine import Engine, EngineConfig
from importlib.metadata import version, PackageNotFoundError


def get_version():
    try:
        return version("iocx")
    except PackageNotFoundError:
        return "0.0.0"


def main():
    parser = argparse.ArgumentParser(
        description="Static IOC extractor for binaries, logs, and text.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
        nargs="?",
        help="File path or raw text. Use '-' to read from stdin.",
    )

    # ---------------------------
    # Output
    # ---------------------------
    output_group.add_argument(
        "-o", "--output",
        help="Write JSON output to a file instead of stdout."
    )

    output_group.add_argument(
        "-c", "--compact",
        action="store_true",
        help="Output compact (minified) JSON."
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

    detector_group.add_argument(
        "--list-transformers",
        action="store_true",
        help="List available transformer plugins."
    )

    detector_group.add_argument(
        "--list-enrichers",
        action="store_true",
        help="List available enricher plugins."
    )

    detector_group.add_argument(
        "-m", "--min-length",
        type=int,
        default=4,
        metavar="N",
        help="Minimum printable string length for the string extractor (default: 4)."
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
        print(get_version())
        return

    # ---------------------------
    # Handle --list-detectors
    # ---------------------------
    if args.list_detectors:
        from iocx.detectors.registry import all_detectors

        # Instantiate engine so plugins load
        engine = Engine()
        plugin_registry = engine._plugin_registry

        # Built‑in detectors
        builtin = all_detectors()

        # Plugin detectors
        plugin_dets = []
        for plugin in plugin_registry.detectors:
            meta = plugin.metadata
            plugin_dets.append({
                "category": meta.id,
                "plugin_id": meta.id,
                "version": meta.version,
                "name": meta.name,
            })

        print("Built‑in Detectors:")
        for name in sorted(builtin.keys()):
            print(f" {name}")

        if plugin_dets:
            print("\nPlugin Detectors:")
            for det in plugin_dets:
                print(f" {det['category']} (plugin: {det['plugin_id']} v{det['version']})")

        return

    # ---------------------------
    # Handle --list-transformers
    # ---------------------------
    if args.list_transformers:
        # Instantiate engine so plugins load
        engine = Engine()
        plugin_registry = engine._plugin_registry

        transformers = plugin_registry.transformers

        print("Transformer Plugins:")
        if not transformers:
            print(" (none)")
            return

        for plugin in transformers:
            meta = plugin.metadata
            print(f" {meta.id} (plugin: {meta.name} v{meta.version})")

        return

    # ---------------------------
    # Handle --list-enrichers
    # ---------------------------
    if args.list_enrichers:
        # Instantiate engine so plugins load
        engine = Engine()
        plugin_registry = engine._plugin_registry

        enrichers = plugin_registry.enrichers

        print("Enricher Plugins:")
        if not enrichers:
            print(" (none)")
            return

        for plugin in enrichers:
            meta = plugin.metadata
            print(f" {meta.id} (plugin: {meta.name} v{meta.version})")

        return

    # ---------------------------
    # Validate input for extraction
    # ---------------------------
    if not args.input:
        parser.error("input is required unless using --version or --list-detectors")

    # ---------------------------
    # Configure engine
    # ---------------------------
    config = EngineConfig(
        enable_cache=not args.no_cache,
        min_string_length=args.min_length
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
    indent = None if args.compact else 2

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=indent)
    else:
        json.dump(result, sys.stdout, indent=indent)
        print()


if __name__ == "__main__":
    main()
