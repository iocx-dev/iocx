from __future__ import annotations
import os
from .utils import detect_file_type, spans_overlap, suppress_overlaps, FileType
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from .parsers.pe_parser import parse_pe
from .parsers.string_extractor import extract_strings
from .validators.normalise import normalise_iocs
from .validators.dedupe import dedupe
from .detectors import all_detectors

@dataclass
class EngineConfig:
    min_string_length: int = 4
    enable_cache: bool = True
    enable_magic: bool = True
    fallback_to_strings: bool = True

@dataclass
class EngineCache:
    pe_metadata: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    strings: Dict[str, List[str]] = field(default_factory=dict)
    detections: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)

    def clear(self):
        self.pe_metadata.clear()
        self.strings.clear()
        self.detections.clear()

class Engine:
    def __init__(self, config: Optional[EngineConfig] = None):
        self.config = config or EngineConfig()
        self.cache = EngineCache()

    # ---------- Public API ----------

    def extract(self, path_or_text: str) -> Dict[str, Any]:
        """
        Unified entry point. Detects file type and routes accordingly.
        """
        if self._is_file(path_or_text):
            return self.extract_from_file(path_or_text)
        else:
            return self.extract_from_text(path_or_text)

    def extract_from_file(self, path: str) -> Dict[str, Any]:
        filetype = detect_file_type(path) if self.config.enable_magic else FileType.UNKNOWN

        if filetype == FileType.PE:
            result = self._pipeline_pe(path)
        elif filetype == FileType.TEXT:
            result = self._pipeline_text_file(path)
        else:
            result = self._pipeline_unknown(path)

        return result

    def extract_from_text(self, text: str) -> Dict[str, Any]:
        raw_iocs = self._run_detectors("<text>", text)
        iocs = self._post_process(raw_iocs)

        return {
            "file": None,
            "iocs": iocs,
            "metadata": {},
        }

    # ---------- Pipeline stages ----------

    def _get_pe_metadata(self, path: str) -> Dict[str, Any]:
        if not self.config.enable_cache:
            return parse_pe(path)

        if path not in self.cache.pe_metadata:
            self.cache.pe_metadata[path] = parse_pe(path)
        return self.cache.pe_metadata[path]

    def _get_strings(self, path: str) -> List[str]:
        if not self.config.enable_cache:
            return extract_strings(path, min_length=self.config.min_string_length)

        if path not in self.cache.strings:
            self.cache.strings[path] = extract_strings(
                path, min_length=self.config.min_string_length
            )
        return self.cache.strings[path]

    def _pipeline_pe(self, path: str) -> Dict[str, Any]:
        metadata = self._get_pe_metadata(path)
        strings = self._get_strings(path)

        # Adds strings extracted from the PE resource section into the main string list before running detectors.
        strings.extend(metadata.get("resource_strings", []))

        text = "\n".join(strings)

        raw_iocs = self._run_detectors(path, text)
        iocs = self._post_process(raw_iocs)

        return {
            "file": path,
            "type": "PE",
            "iocs": iocs,
            "metadata": metadata,
        }

    def _pipeline_text_file(self, path: str) -> Dict[str, Any]:
        with open(path, "r", errors="ignore") as f:
            text = f.read()

        raw_iocs = self._run_detectors(path, text)
        iocs = self._post_process(raw_iocs)

        return {
            "file": path,
            "type": "text",
            "iocs": iocs,
            "metadata": {},
        }

    def _pipeline_unknown(self, path: str) -> Dict[str, Any]:
        """
        Unknown file type → fallback to strings if enabled.
        """
        if not self.config.fallback_to_strings:
            return {
                "file": path,
                "type": "unknown",
                "iocs": {},
                "metadata": {},
            }

        strings = self._get_strings(path)
        text = "\n".join(strings)

        raw_iocs = self._run_detectors(path, text)
        iocs = self._post_process(raw_iocs)

        return {
            "file": path,
            "type": "unknown",
            "iocs": iocs,
            "metadata": {},
        }

    def _run_detectors(self, key: str, text: str) -> Dict[str, Any]:
        if self.config.enable_cache and key in self.cache.detections:
            return self.cache.detections[key]

        detections: Dict[str, Any] = {}

        for name, detector in all_detectors().items():
            result = detector(text)

            # Allow detectors to return either:
            # - list[str]
            # - dict[str, list[str]]
            detections[name] = result

        if self.config.enable_cache:
            self.cache.detections[key] = detections

        return detections

    def _post_process(self, raw_iocs):
        """
        Combine detector outputs, suppress overlaps, and return clean IOC lists.
        """

        # 1. Flatten all detector outputs into a single list
        all_matches = []
        for items in raw_iocs.values():
            for value, start, end, category in items:
                all_matches.append((value, start, end, category))

        # 2. Sort by start position, then by longest span first
        all_matches.sort(key=lambda m: (m[1], -(m[2] - m[1])))

        # 3. Suppress overlaps globally
        survivors = []
        last_end = -1

        for value, start, end, category in all_matches:
            if start >= last_end:
                survivors.append((value, start, end, category))
                last_end = end

        # 4. Rebuild category lists
        merged = {
            "urls": [],
            "domains": [],
            "ips": [],
            "emails": [],
            "filepaths": [],
            "hashes": [],
            "base64": [],
        }

        for value, start, end, category in survivors:
            merged[category].append(value)

        return merged


    # ---------- Helpers ----------

    def _is_file(self, value: str) -> bool:
        try:
            return os.path.exists(value)
        except Exception:
            return False
