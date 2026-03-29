import importlib.metadata
import importlib.util
from pathlib import Path
import logging

from .registry import PluginRegistry

ENTRYPOINT_GROUP = "iocx.plugins"


class PluginLoader:
    def __init__(self) -> None:
        self.registry = PluginRegistry()
        self.logger = logging.getLogger("iocx.plugins")

    def load_all(self) -> PluginRegistry:
        self._load_entrypoint_plugins()
        self._load_local_plugins()
        return self.registry

    # -------------------------
    # Plugin validation (duck typing)
    # -------------------------
    def _is_valid_plugin(self, plugin) -> bool:
        return (
            hasattr(plugin, "metadata")
            and (
                hasattr(plugin, "detect")
                or hasattr(plugin, "transform")
                or hasattr(plugin, "enrich")
            )
        )

    # -------------------------
    # Entrypoint plugins
    # -------------------------
    def _load_entrypoint_plugins(self) -> None:
        try:
            eps = importlib.metadata.entry_points()
            group = eps.select(group=ENTRYPOINT_GROUP)
        except Exception as e:
            self.logger.warning(f"[iocx] Failed to enumerate entrypoints: {e}")
            group = []

        for ep in group:
            try:
                plugin_cls = ep.load()
                plugin = plugin_cls() # instantiate first

                if not self._is_valid_plugin(plugin):
                    self.logger.warning(
                        f"[iocx] Entrypoint '{ep.name}' is not a valid IOCX plugin"
                    )
                    continue

                self.registry.register(plugin)

            except Exception as e:
                self.logger.error(
                    f"[iocx] Failed to load plugin '{ep.name}': {e}",
                    exc_info=True,
                )

    # -------------------------
    # Local plugins (~/.iocx/plugins)
    # -------------------------
    def _load_local_plugins(self) -> None:
        local_dir = Path.home() / ".iocx" / "plugins"
        if not local_dir.exists():
            return

        for file in local_dir.glob("*.py"):
            try:
                spec = importlib.util.spec_from_file_location(file.stem, file)
                if spec is None or spec.loader is None:
                    self.logger.warning(
                        f"[iocx] Could not load spec for local plugin {file}"
                    )
                    continue

                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                plugin_cls = getattr(module, "Plugin", None)
                if plugin_cls is None:
                    self.logger.warning(
                        f"[iocx] Local plugin {file} has no Plugin class"
                    )
                    continue

                plugin = plugin_cls() # instantiate first

                if not self._is_valid_plugin(plugin):
                    self.logger.warning(
                        f"[iocx] Local plugin {file} is not a valid IOCX plugin"
                    )
                    continue

                self.registry.register(plugin)

            except Exception as e:
                self.logger.error(
                    f"[iocx] Failed to load local plugin {file}: {e}",
                    exc_info=True,
                )
                continue
