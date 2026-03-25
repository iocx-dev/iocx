from typing import List, Dict
from .api import IOCXPlugin

class PluginRegistry:
    def __init__(self):
        self.detectors: List[IOCXPlugin] = []
        self.enrichers: List[IOCXPlugin] = []
        self.transformers: List[IOCXPlugin] = []

    def register(self, plugin: IOCXPlugin):
        caps = getattr(plugin, "metadata", None)
        if caps is None:
            return

        capabilities = plugin.metadata.capabilities

        if "detector" in capabilities:
            self.detectors.append(plugin)
        if "enricher" in capabilities:
            self.enrichers.append(plugin)
        if "transformer" in capabilities:
            self.transformers.append(plugin)
