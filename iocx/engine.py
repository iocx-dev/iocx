from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from .utils import detect_file_type, spans_overlap, suppress_overlaps, FileType
from .parsers.pe_parser import parse_pe
from .parsers.string_extractor import extract_strings
from .validators.normalise import normalise_iocs
from .validators.dedupe import dedupe
from .detectors import all_detectors
from .models import Detection


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
    detections: Dict[str, Dict[str, List[Detection]]] = field(default_factory=dict)

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
        if self._is_file(path_or_text):
            return self.extract_from_file(path_or_text)
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
        raw = self._run_detectors("<text>", text)
        iocs = self._post_process(raw)
        return {"file": None, "iocs": iocs, "metadata": {}}

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
        strings.extend(metadata.get("resource_strings", []))

        text = "\n".join(strings)
        raw = self._run_detectors(path, text)
        iocs = self._post_process(raw)

        return {"file": path, "type": "PE", "iocs": iocs, "metadata": metadata}

    def _pipeline_text_file(self, path: str) -> Dict[str, Any]:
        with open(path, "r", errors="ignore") as f:
            text = f.read()

        raw = self._run_detectors(path, text)
        iocs = self._post_process(raw)

        return {"file": path, "type": "text", "iocs": iocs, "metadata": {}}

    def _pipeline_unknown(self, path: str) -> Dict[str, Any]:
        if not self.config.fallback_to_strings:
            return {"file": path, "type": "unknown", "iocs": {}, "metadata": {}}

        strings = self._get_strings(path)
        text = "\n".join(strings)

        raw = self._run_detectors(path, text)
        iocs = self._post_process(raw)

        return {"file": path, "type": "unknown", "iocs": iocs, "metadata": {}}

    # ---------- Detector execution ----------

    def _run_detectors(self, key: str, text: str) -> Dict[str, List[Detection]]:
        if self.config.enable_cache and key in self.cache.detections:
            return self.cache.detections[key]

        results: Dict[str, List[Detection]] = {}

        for name, detector in all_detectors().items():
            detections = detector(text)

            # Normalise detector output:
            # - detectors now return List[Detection]
            # - legacy detectors returning tuples are converted
            normalised: List[Detection] = []
            for item in detections:
                if isinstance(item, Detection):
                    normalised.append(item)
                else:
                    value, start, end, category = item
                    normalised.append(Detection(value, start, end, category))

            results[name] = normalised

        if self.config.enable_cache:
            self.cache.detections[key] = results

        return results

    # ---------- Post-processing ----------

    def _post_process(self, raw: Dict[str, List[Detection]]) -> Dict[str, List[str]]:
        # 1. Flatten
        all_matches: List[Detection] = [
            det for detector_list in raw.values() for det in detector_list
        ]

        # 2. Sort by start, then longest span first
        all_matches.sort(key=lambda d: (d.start, -(d.end - d.start)))

        # 3. Suppress overlaps
        survivors: List[Detection] = []
        last_end = -1

        for det in all_matches:
            if det.start >= last_end:
                survivors.append(det)
                last_end = det.end

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

        for det in survivors:
            merged[det.category].append(det.value)

        return merged

    # ---------- Helpers ----------

    def _is_file(self, value: str) -> bool:
        try:
            return os.path.exists(value)
        except Exception:
            return False
