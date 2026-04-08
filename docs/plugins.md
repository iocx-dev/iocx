# Overview

IOCX supports three plugin types:

- Detectors — extract IOCs from text
- Enrichers — add context to extracted IOCs
- Transformers — modify text before detection

All plugins implement the `IOCXPlugin` protocol and expose a metadata object describing their capabilities.

Plugins are automatically registered into the engine’s `PluginRegistry` based on their declared capabilities.

1. Plugin Interface

All plugins must implement the `IOCXPlugin` protocol:

```python
class IOCXPlugin(Protocol):
    metadata: PluginMetadata

    def detect(self, text: str, ctx: PluginContext) -> List[Detection]:
        ...

    def enrich(self, text: str, ctx: PluginContext) -> None:
        ...

    def transform(self, text: str, ctx: PluginContext) -> str:
        ...
```
✔ Required

`metadata`: `PluginMetadata`

✔ Optional methods

Plugins may implement any subset of:

- detect() → return a list of Detection
- enrich() → modify IOC context (in-place)
- transform() → return transformed text

If a method is not implemented, the plugin simply does not participate in that stage of the pipeline.

2. Plugin Metadata

Every plugin must define a `PluginMetadata` instance:

```python
@dataclass(frozen=True)
class PluginMetadata:
    id: str
    name: str
    version: str
    description: str
    author: str
    capabilities: List[str] # ["detector", "enricher", "transformer"]
    iocx_min_version: str
```

Field descriptions:

| Field            | Type        | Description                                           |
|------------------|-------------|-------------------------------------------------------|
| id               | str         | Unique, stable identifier (e.g., mutex-detector)      |
| name             | str         | Human‑readable plugin name                            |
| version          | str         | Plugin version (SemVer recommended)                   |
| description      | str         | Short explanation of what the plugin does             |
| author           | str         | Plugin author or maintainer                           |
| capabilities     | List[str]   | One or more of: "detector", "enricher", "transformer" |
| iocx_min_version | str         | Minimum compatible iocx version                       |

Example metadata:

```python
metadata = PluginMetadata(
    id="mutex-detector",
    name="Mutex Detector",
    version="0.1.0",
    description="Extracts Windows mutex names from text.",
    author="MalX Labs",
    capabilities=["detector"],
    iocx_min_version="0.4.0",
)
```

3. Plugin Methods

3.1 detect(text, ctx) -> List[Detection]

- Extract IOCs from raw text.
- Should return a list of Detection objects.
- Should not mutate input.
- Should not raise exceptions for malformed input.

Example:

```python
def detect(self, text: str, ctx: PluginContext) -> List[Detection]:
    results = []
    if "MUTEX_" in text:
        results.append(Detection(type="mutex", value="MUTEX_ABC"))
    return results
```

3.2 enrich(text, ctx) -> None

- Add context to previously extracted IOCs.
- Does not return anything.
- Should modify ctx or IOC objects in place.

Example:

```python
def enrich(self, text: str, ctx: PluginContext) -> None:
    for ioc in ctx.iocs:
        if ioc.type == "ip":
            ioc.metadata["source"] = "basic-enricher"
```

3.3 transform(text, ctx) -> str

- Modify text before detection.
- Must return the transformed text.
- Should be deterministic.

Example:

```python
def transform(self, text: str, ctx: PluginContext) -> str:
    return text.lower()
```

4. Plugin Registration

Plugins are registered via the `PluginRegistry`:

```python
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
```

Registration rules:

- Plugins must define metadata.
- Plugins are added to one or more lists based on metadata.capabilities.
- Missing or invalid metadata → plugin is ignored.
- Order of registration determines execution order.

5. Execution Pipeline

The engine processes plugins in three phases:

1. Transformers

Executed first, in registration order:

```Code
text → transform → transform → transform → detectors
```

2. Detectors

Each detector receives the transformed text:

```Code
detector1 → detector2 → detector3
```

Each returns a list of Detection.

3. Enrichers

Executed last, modifying IOC context:

```Code
enricher1 → enricher2 → enricher3
```

6. Minimal Example Plugin

```python
from iocx.api import IOCXPlugin
from iocx.metadata import PluginMetadata
from iocx.models import Detection, PluginContext

class ExamplePlugin:
    metadata = PluginMetadata(
        id="example",
        name="Example Plugin",
        version="0.1.0",
        description="A minimal example plugin.",
        author="MalX Labs",
        capabilities=["detector"],
        iocx_min_version="0.4.0",
    )

    def detect(self, text: str, ctx: PluginContext):
        if "IOC" in text:
            return [Detection(type="example", value="IOC")]
        return []
```

7. Best Practices

- Keep detectors pure and deterministic.
- Avoid expensive operations inside detect().
- Use transform() for normalisation.
- Use enrich() for metadata, not detection.
- Validate plugin metadata before publishing.
- Follow semantic versioning for plugin releases.

8. Compatibility Guarantees

Plugins should declare:

```python
iocx_min_version="0.4.0"
```

The engine may refuse to load plugins requiring a newer version
