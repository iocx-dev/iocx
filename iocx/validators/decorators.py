# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

from typing import Literal, Tuple

Layer = Literal["internal", "metadata", "analysis"]

def depends_on(*layers: Layer):
    """
    Annotate a validator with the layers it requires.
    Valid layers: "internal", "metadata", "analysis".
    """
    def wrap(fn):
        fn._depends_on: Tuple[Layer, ...] = layers
        return fn
    return wrap
