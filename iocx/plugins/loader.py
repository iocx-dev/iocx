import importlib.metadata
import importlib.util
from pathlib import Path

from .registry import PluginRegistry
from .api import IOCXPlugin

ENTRYPOINT_GROUP = "iocx.plugins"


class PluginLoader:
    def __init__(self) -> None:
        self.registry = PluginRegistry()

    def load_all(self) -> PluginRegistry:
        self._load_entrypoint_plugins()
        self._load_local_plugins()
        return self.registry

    def _load_entrypoint_plugins(self) -> None:
        try:
            eps = importlib.metadata.entry_points()
            group = eps.select(group=ENTRYPOINT_GROUP)
        except Exception:
            group = []

        for ep in group:
            try:
                plugin_cls = ep.load()
                plugin = plugin_cls()
                self.registry.register(plugin)
            except Exception as e:
                # TODO: replace with logger
                print(f"[iocx] Failed to load plugin {ep.name}: {e}")


    def _load_local_plugins(self) -> None:
        """
        Load plugins from ~/.iocx/plugins/*.py for local development.
        Each file must define a `Plugin` class.
        """
        local_dir = Path.home() / ".iocx" / "plugins"
        if not local_dir.exists():
            return

        for file in local_dir.glob("*.py"):
            try:
                spec = importlib.util.spec_from_file_location(file.stem, file)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                plugin_cls = getattr(module, "Plugin", None)
                if plugin_cls is None:
                    continue

                plugin: IOCXPlugin = plugin_cls()
                self.registry.register(plugin)
            except Exception:
                # TODO: hook into logger instead of print
                # print(f"[iocx] Failed to load local plugin {file}: {e}")
                continue
