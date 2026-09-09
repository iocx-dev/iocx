# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import argparse
import json
import sys
from ..engine import Engine, EngineConfig
from importlib.metadata import version, PackageNotFoundError

_ART = r"""  ___ ___   ___ __  __
 |_ _/ _ \ / __|\ \/ /
  | | (_) | (__  >  <
 |___\___/ \___|/_/\_\
"""

def _dep_version(name: str) -> str:
    """Best-effort dependency version; never raises."""
    try:
        from importlib.metadata import version
        return version(name)
    except Exception:
        return "unknown"


def _format_version(version: str, *, art: bool = True) -> str:
    """
    Build the --version text.

    Dependency versions are included because they are a real variable in
    the output: pefile materialises the resource tree the parsers walk,
    so two runs disagreeing on a finding may differ only there.
    """
    lines = []

    # ASCII art only when stdout is a terminal - it is noise in CI logs
    # and in anything capturing the output.
    if art and sys.stdout.isatty():
        lines.append(_ART.rstrip("\n"))
        lines.append("")

    py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    lines.extend([
        f"Deterministic PE static analysis\n",
        f"iocx    {version}",
        f"python  {py}",
        f"pefile  {_dep_version('pefile')}",
        "license MPL-2.0",
        "",
        "MalX Labs - https://github.com/iocx-dev/iocx",
    ])

    return "\n".join(lines)


def get_version():
    try:
        return _format_version(version("iocx"))
    except PackageNotFoundError:
        return "0.0.0"


def main():
    parser = argparse.ArgumentParser(
        description="An extensible, deterministic static‑analysis engine that extracts high‑signal IOCs from PE binaries and text, built for SOC automation and modern threat‑analysis pipelines.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False
    )

    # ---------------------------
    # Argument Groups
    # ---------------------------
    input_group = parser.add_argument_group("Input")
    output_group = parser.add_argument_group("Output")
    pe_analysis_group = parser.add_argument_group("PE Analysis")
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

    output_group.add_argument(
        "-e", "--enrich",
        action="store_true",
        help="Write enrichment data to the JSON output. Enrichment is context to extracted IOCs, surfaced via plugins with the enrichment capability."
    )

    pe_analysis_group.add_argument(
        "-a", "--analyse", "--analyze",
        nargs="?",
        const="deep",
        choices=["basic", "deep", "full"],
        metavar="LEVEL",
        help="Enable PE analysis. LEVEL: basic (sections, entropy), deep (+ obfuscation heuristics), full (+ structural validation, full version-info). Default when -a is given without a value: deep."
    )

    # ---------------------------
    # Engine Options
    # ---------------------------
    engine_group.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable engine caching."
    )

    engine_group.add_argument(
        "-m", "--min-length",
        type=int,
        default=4,
        metavar="N",
        help="Minimum printable string length for the string extractor (default: 4)."
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
        help="List available transformer plugins and exit."
    )

    detector_group.add_argument(
        "--list-enrichers",
        action="store_true",
        help="List available enricher plugins and exit."
    )

    # ---------------------------
    # Misc
    # ---------------------------
    misc_group.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit."
    )

    misc_group.add_argument(
        "-d", "--dev",
        action="store_true",
        help="Enable local plugins. Local plugins must be placed in the '.iocx/plugins' folder of your home directory.",
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

    # ----------------------------
    # Local plugins loading notification
    # ----------------------------
    if args.dev:
        print("\x1b[33m[dev] Loading local plugins…\x1b[0m", file=sys.stderr)

    # ---------------------------
    # Configure engine
    # ---------------------------
    config = EngineConfig(
        enable_cache=not args.no_cache,
        min_string_length=args.min_length,
        enable_local_plugins=args.dev,
        analysis_level=args.analyse
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

    if args.enrich:
        ctx = engine.plugin_context
        result["enrichment"] = ctx.metadata


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
