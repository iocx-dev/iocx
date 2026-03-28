from typing import Protocol, List
from .metadata import PluginMetadata
from iocx.models import Detection, PluginContext


class IOCXPlugin(Protocol):
    """
    Base interface for all iocx plugins.
    """

    metadata: PluginMetadata

    def detect(self, text: str, ctx: PluginContext) -> List[Detection]:
        """
        Optional: Extract IOCs from text.
        """
        ...

    def enrich(self, text: str, ctx: PluginContext) -> None:
        """
        Optional: Enrich an IOC with additional context.
        """
        ...

    def transform(self, text: str, ctx: PluginContext) -> str:
        """
        Optional: Transform text before detection.
        """
        ...
