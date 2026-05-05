from typing import Dict, Any

from .sections import validate_sections
from .entrypoint import validate_entrypoint
from .rva_graph import validate_rva_graph
from .optional_header import validate_optional_header
from .tls import validate_tls
from .signature import validate_signature
from .entropy import validate_entropy


def run_structural_validators(metadata: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run all structural validators in a deterministic order and return the
    complete structural analysis dictionary. This output is attached to
    analysis["structural"] and consumed by the heuristics layer.

    Each validator must return a List[StructuralIssue].
    """

    return {
        # Entrypoint mapping correctness
        "entrypoint": validate_entrypoint(metadata, analysis),

        # Section flags, names, alignment, overlap, impossible combinations
        "sections": validate_sections(metadata, analysis),

        # Optional header consistency (e.g., SizeOfImage)
        "optional_header": validate_optional_header(metadata, analysis),

        # RVA graph consistency (directory bounds, overlaps, out-of-range)
        "data_directories": validate_rva_graph(metadata, analysis),

        # TLS callback range correctness
        "tls": validate_tls(metadata, analysis),

        # Signature directory correctness
        "signature": validate_signature(metadata, analysis),

        # Entropy metrics (high entropy sections, overlays, uniform patterns)
        "entropy": validate_entropy(metadata, analysis),
    }
