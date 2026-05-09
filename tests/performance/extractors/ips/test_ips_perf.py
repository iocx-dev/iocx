# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
import time
import random
import string
from iocx.detectors.extractors.ips import extract


def random_ipv4():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


def random_ipv6():
    groups = [f"{random.randint(0, 0xFFFF):x}" for _ in range(8)]
    return ":".join(groups)


def random_noise(n=200):
    chars = string.ascii_letters + string.digits + ":./[]%_-"
    return "".join(random.choice(chars) for _ in range(n))


def build_large_input(size_kb=500):
    chunks = []
    for _ in range(size_kb):
        choice = random.randint(1, 10)
        if choice <= 3:
            chunks.append(random_ipv4())
        elif choice <= 6:
            chunks.append(random_ipv6())
        else:
            chunks.append(random_noise(50))
    return " ".join(chunks)

@pytest.mark.performance
def test_detector_large_input_performance():
    text = build_large_input(1000)  # ~1MB of mixed content
    start = time.perf_counter()
    result = extract(text)
    duration = time.perf_counter() - start

    print(f"[perf] IP 1MB mixed-content: {duration:.4f}s")

    # Assert performance threshold
    assert duration < 1.0, f"IP detector too slow: {duration:.3f}s"


@pytest.mark.performance
def test_detector_pathological_performance():
    # Worst-case for regex and exception-heavy parsing
    pathological = ":".join("ffff" for _ in range(5000))  # giant IPv6-like blob

    start = time.perf_counter()
    result = extract(pathological)
    duration = time.perf_counter() - start

    print(f"[perf] pathological IPv6 blob: {duration:.4f}s")

    assert duration < 0.5, f"IP pathological input too slow: {duration:.3f}s"


@pytest.mark.performance
def test_scaling_behavior():
    sizes = [100, 300, 600, 1000]  # KB
    timings = []

    for size in sizes:
        text = build_large_input(size)
        start = time.perf_counter()
        extract(text)
        duration = time.perf_counter() - start
        timings.append(duration)
        print(f"[perf] IP {size}KB: {duration:.4f}s")

    # Ensure roughly linear scaling
    for i in range(1, len(timings)):
        assert timings[i] < timings[i-1] * 4.0, "Non-linear scaling detected"
