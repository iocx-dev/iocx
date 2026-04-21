from __future__ import annotations
import os
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Any, List, Optional
from .utils import detect_file_type, FileType
from .parsers.pe_parser import parse_pe, analyse_pe_sections
from .parsers.string_extractor import extract_strings
from .detectors import all_detectors
from .models import Detection, PluginContext
from .plugins.loader import PluginLoader
from .analysis.obfuscation import analyse_obfuscation
from .analysis.extended import analyse_extended
from .analysis.heuristics import analyse_pe_heuristics

@dataclass
class EngineConfig:
    min_string_length: int = 4
    enable_cache: bool = True
    enable_magic: bool = True
    fallback_to_strings: bool = True
    enable_local_plugins: bool = False
    analysis_level: str = None


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

    @property
    def plugin_context(self):
        return self._plugin_context

    @property
    def depth(self):
        return self.depth_stack[-1]

    def __init__(self, config: Optional[EngineConfig] = None):
        self.config = config or EngineConfig()
        self.cache = EngineCache()

        # load plugins once per engine instance
        self._plugin_loader = PluginLoader(
            enable_local_plugins=self.config.enable_local_plugins
        )
        self._plugin_registry = self._plugin_loader.load_all()

        self._plugin_context: Optional[PluginContext] = None

        self.depth_stack = [0]

        self._analysis_level = self.config.analysis_level

    # ---------- Public API ----------

    def extract(self, path_or_text: str) -> Dict[str, Any]:
        if self._is_file(path_or_text):
            return self.extract_from_file(path_or_text)
        return self.extract_from_text(path_or_text)

    def extract_from_file(self, path: str) -> Dict[str, Any]:
        filetype = detect_file_type(path) if self.config.enable_magic else FileType.UNKNOWN

        if filetype == FileType.PE:
            return self._pipeline_pe(path)
        elif filetype == FileType.TEXT:
            return self._pipeline_text_file(path)
        elif filetype in (FileType.ZIP, FileType.TAR, FileType.SEVEN_Z):
            return self._pipeline_archive(path)
        else:
            return self._pipeline_unknown(path)

    def extract_from_text(self, text: str) -> Dict[str, Any]:
        raw = self._run_detectors("<text>", text)
        iocs = self._post_process(raw)
        return {"file": None, "type": "text", "iocs": iocs, "metadata": {}}

    # ---------- Pipeline stages ----------

    def _get_pe_metadata(self, path: str):
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
        pe, metadata = self._get_pe_metadata(path)
        strings = self._get_strings(path)
        strings.extend(metadata.get("resource_strings", []))
        text = "\n".join(strings)

        analysis_level = self._analysis_level
        section_analysis = []
        obf = []
        extended = None
        heuristics = []

        # BASIC: section layout + entropy
        if analysis_level in ("basic", "deep", "full"):
            section_analysis = analyse_pe_sections(pe)

        # DEEP: obfuscation heuristics
        if analysis_level in ("deep", "full"):
            obf = analyse_obfuscation(section_analysis, text)

        # FULL: future expansion
        if analysis_level == "full":
            extended = analyse_extended(pe, metadata, text)

            analysis_dict = {
                "sections": section_analysis,
                "data_directories": metadata.get("data_directories", []),
                "extended": extended or [],
                "obfuscation": [asdict(d) for d in obf],
            }

            heuristics = analyse_pe_heuristics(metadata, analysis_dict)

        raw = self._run_detectors(path, text)
        iocs = self._post_process(raw)

        result = {"file": path, "type": "PE", "iocs": iocs, "metadata": metadata}

        analysis = {}

        if analysis_level in ("basic", "deep", "full"):
            analysis["sections"] = section_analysis

        if analysis_level in ("deep", "full"):
            analysis["obfuscation"] = [asdict(d) for d in obf]

        if analysis_level == "full" and extended is not None:
            analysis["extended"] = extended
            analysis["heuristics"] = [asdict(h) for h in heuristics]

        if analysis:
            result["analysis"] = analysis

        return result


    def _pipeline_text_file(self, path: str) -> Dict[str, Any]:
        with open(path, "r", errors="ignore") as f:
            text = f.read()

        raw = self._run_detectors(path, text)
        iocs = self._post_process(raw)

        return {"file": path, "type": "text", "iocs": iocs, "metadata": {}}

    def _pipeline_unknown(self, path: str) -> Dict[str, Any]:
        if not self.config.fallback_to_strings:
            # still store a context for consistency
            self._plugin_context = self._build_plugin_context(path, "")
            return {"file": path, "type": "unknown", "iocs": {}, "metadata": {}}

        strings = self._get_strings(path)
        text = "\n".join(strings)

        raw = self._run_detectors(path, text)
        iocs = self._post_process(raw)

        return {"file": path, "type": "unknown", "iocs": iocs, "metadata": {}}

    def _pipeline_archive(self, path: str) -> Dict[str, Any]:
        raw = self._run_detectors(path, "")
        iocs = self._post_process(raw)

        return {"file": path, "type": "archive", "iocs": iocs, "metadata": {}}

    # ---------- Detector execution ----------

    def _build_plugin_context(self, key: str, text: str) -> PluginContext:
        return PluginContext(
            file_path=Path(key) if key != "<text>" else None,
            raw_text=text,
            logger=self._logger(),
            config={},
            detections={},
            engine=self,
            metadata={},
        )

    def _run_detectors(self, key: str, text: str) -> Dict[str, List[Detection]]:
        if self.config.enable_cache and key in self.cache.detections:
            ctx = self._build_plugin_context(key, text)
            ctx.detections = self.cache.detections[key]
            self._plugin_context = ctx
            return self.cache.detections[key]

        results: Dict[str, List[Detection]] = {}

        ctx = self._build_plugin_context(key, text)

        for plugin in self._plugin_registry.transformers:
            try:
                text = plugin.transform(text, ctx)
            except Exception as e:
                ctx.logger.warning(f"[iocx] transformer plugin {plugin.metadata.id} failed: {e}")

        for name, detector in all_detectors().items():
            raw = detector(text)

            # Normalise detector output into a flat list of items
            if isinstance(raw, dict):
                # Super-detector: flatten all lists
                items = []
                for sublist in raw.values():
                    if isinstance(sublist, list):
                        items.extend(sublist)

                if not items: # if dict has no valid lists, skip it
                    results[name] = []
                    continue
            elif isinstance(raw, list):
                items = raw
            else:
                # Completely invalid detector output → skip
                results[name] = []
                continue

            normalised: List[Detection] = []

            for item in items:
                if isinstance(item, Detection):
                    normalised.append(item)
                elif isinstance(item, (list, tuple)) and len(item) == 4:
                    value, start, end, category = item
                    normalised.append(Detection(value, start, end, category))
                else:
                    # Skip malformed items instead of crashing
                    continue

            results[name] = normalised

        for plugin in self._plugin_registry.detectors:
            try:
                raw = plugin.detect(text, ctx)
            except Exception as e:
                ctx.logger.warning(f"[iocx] detector plugin {plugin.metadata.id} failed: {e}")
                continue

            if isinstance(raw, dict):
                # Preserve categories exactly as returned
                for category, items in raw.items():
                    normalised = []
                    for item in items:
                        if isinstance(item, Detection):
                            normalised.append(item)
                        elif isinstance(item, (list, tuple)) and len(item) == 4:
                            value, start, end, category2 = item
                            normalised.append(Detection(value, start, end, category2))
                    results[category] = normalised
                continue

            items = raw or []
            normalised: List[Detection] = []

            for item in items:
                if isinstance(item, Detection):
                    normalised.append(item)
                elif isinstance(item, (list, tuple)) and len(item) == 4:
                    value, start, end, category = item
                    normalised.append(Detection(value, start, end, category))
                else:
                    continue

            results[plugin.metadata.id] = normalised


        ctx.detections = results

        if self.config.enable_cache:
            self.cache.detections[key] = results

        self._plugin_context = ctx

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

        # 4. Normalise
        CASE_INSENSITIVE = {"domains", "emails", "hashes"}

        for det in survivors:
            v = det.value.strip()
            if det.category in CASE_INSENSITIVE:
                v = v.lower()
            det.value = v

        # 5. Group by category (keep Detection objects)
        grouped = {}
        for det in survivors:
            grouped.setdefault(det.category, []).append(det)

        # 6. Dedupe once per category (order‑preserving)
        for key, dets in grouped.items():
            seen = set()
            uniq = []
            for det in dets:
                if det.value not in seen:
                    seen.add(det.value)
                    uniq.append(det)
            grouped[key] = uniq

        # 7. Ensure all categories exist
        baseline = {
            "urls": [],
            "domains": [],
            "ips": [],
            "hashes": [],
            "emails": [],
            "filepaths": [],
            "base64": [],
            "crypto.btc": [],
            "crypto.eth": [],
        }
        baseline.update(grouped)

        # 8. Run enrichers
        ctx = self._build_plugin_context("<merged>", "")
        ctx.detections = baseline

        # ensure metadata exists
        for dets in ctx.detections.values():
            for det in dets:
                if det.metadata is None:
                    det.metadata = {}

        for plugin in self._plugin_registry.enrichers:
            try:
                plugin.enrich("", ctx)
            except Exception as e:
                ctx.logger.warning(f"[iocx] enricher plugin {plugin.metadata.id} failed: {e}")

        # Save enrichment metadata for pipeline to attach
        if self._plugin_context is None:
            self._plugin_context = self._build_plugin_context("<post>", "")

        self._plugin_context.metadata = ctx.metadata

        # 9. Convert Detection objects → strings
        final = {cat: [det.value for det in dets] for cat, dets in ctx.detections.items()}

        return final


    # ---------- Helpers ----------

    def _is_file(self, value: str) -> bool:
        try:
            return os.path.exists(value)
        except Exception:
            return False

    def _logger(self):
        return logging.getLogger("iocx")


    def analyze_file(self, path: str) -> List[Detection]:
        # Enter recursion
        self.depth_stack.append(self.depth + 1)

        try:
            ctx = self._build_plugin_context(path, "")
            result = self.extract_from_file(path)
        finally:
            # Leave recursion
            self.depth_stack.pop()

        detections: List[Detection] = []

        # Convert engine IOC output into Detection objects
        for category, values in result["iocs"].items():
            for value in values:
                detections.append(
                    Detection(
                        category=category,
                        value=value,
                        start=0,
                        end=0,
                    )
                )

        return detections
