# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from dataclasses import dataclass
from typing import List

@dataclass(frozen=True)
class PluginMetadata:
    id: str
    name: str
    version: str
    description: str
    author: str
    capabilities: List[str]  # ["detector", "enricher", "transformer"]
    iocx_min_version: str
