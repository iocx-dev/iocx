# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from typing import Dict, Any

from .sections import validate_sections
from .entrypoint import validate_entrypoint
from .rva_graph import validate_rva_graph
from .optional_header import validate_optional_header
from .tls import validate_tls
from .signature import validate_signature
from .resources import validate_resources
from .entropy import validate_entropy

STRUCTURAL_VALIDATORS = {
    # Entrypoint mapping correctness
    "entrypoint": validate_entrypoint,
    # Section flags, names, alignment, overlap, impossible combinations
    "sections": validate_sections,
    # Optional header consistency (e.g., SizeOfImage)
    "optional_header": validate_optional_header,
    # RVA graph consistency (directory bounds, overlaps, out-of-range)
    "data_directories": validate_rva_graph,
    # TLS callback range correctness
    "tls": validate_tls,
    # Signature directory correctness
    "signature": validate_signature,
    # Resource directory correctness
    "resources": validate_resources,
    # Entropy metrics (high entropy sections, overlays, uniform patterns)
    "entropy": validate_entropy,
}

def run_structural_validators(internal, metadata, analysis):
    """
    Run all structural validators in a deterministic order and return the
    complete structural analysis dictionary. This output is attached to
    analysis["structural"] and consumed by the heuristics layer.

    Each validator must return a List[StructuralIssue].
    """
    def call(validator):
        deps = getattr(validator, "_depends_on", ("metadata", "analysis"))

        args = []
        if "internal" in deps:
            args.append(internal)
        if "metadata" in deps:
            args.append(metadata)
        if "analysis" in deps:
            args.append(analysis)

        return validator(*args)

    return {name: call(fn) for name, fn in STRUCTURAL_VALIDATORS.items()}
