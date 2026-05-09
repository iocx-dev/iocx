# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from typing import TypedDict, Dict, List, Any


class StructuralIssue(TypedDict, total=False):
    """
    A single structural anomaly detected by a validator.
    """
    issue: str # canonical reason code (from ReasonCodes)
    details: Dict[str, Any] # structured metadata describing the anomaly


class StructuralAnalysis(TypedDict):
    """
    The complete structural validation output attached to analysis["structural"].

    Each key corresponds to a validator category and contains a list of
    StructuralIssue objects. Validators must populate these lists deterministically.
    """
    entrypoint: List[StructuralIssue]
    sections: List[StructuralIssue]
    optional_header: List[StructuralIssue]
    data_directories: List[StructuralIssue]
    tls: List[StructuralIssue]
    signature: List[StructuralIssue]
    imports: List[StructuralIssue]
    entropy: List[StructuralIssue]
