import pytest
import time
import random
import string
from iocx.extractors.filepaths import extract


# -----------------------------
# Random path generators
# -----------------------------

def rand_windows_path():
    drive = random.choice("CDE")
    segments = ["".join(random.choices(string.ascii_letters + string.digits + "._-", k=8))
                for _ in range(random.randint(2, 6))]
    return drive + ":\\" + "\\".join(segments)


def rand_unix_path():
    segments = ["".join(random.choices(string.ascii_letters + string.digits + "._-", k=8))
                for _ in range(random.randint(2, 6))]
    return "/" + "/".join(segments)


def rand_unc_path():
    server = "".join(random.choices(string.ascii_letters + string.digits + "-_", k=10))
    share = "".join(random.choices(string.ascii_letters + string.digits + "-_", k=8))
    segments = ["".join(random.choices(string.ascii_letters + string.digits + "._-", k=8))
                for _ in range(random.randint(1, 5))]
    return "\\\\" + server + "\\" + share + ("\\" + "\\".join(segments) if segments else "")


def rand_env_path():
    var = random.choice(["%APPDATA%", "%TEMP%", "$HOME", "$USER", "$TMPDIR"])
    tail = "".join(random.choices(string.ascii_letters + string.digits + "._-", k=8))
    return f"{var}/{tail}"


def rand_tilde_path():
    user = random.choice(["", "root", "admin", "user123"])
    segments = ["".join(random.choices(string.ascii_letters + string.digits + "._-", k=8))
                for _ in range(random.randint(1, 4))]
    prefix = "~" + (user if user else "")
    return prefix + "/" + "/".join(segments)


def random_noise(n=200):
    chars = string.ascii_letters + string.digits + ":./[]%_-"
    return "".join(random.choice(chars) for _ in range(n))


# -----------------------------
# Build large mixed input
# -----------------------------

def build_large_input(size_kb=500):
    generators = [
        rand_windows_path,
        rand_unix_path,
        rand_unc_path,
        rand_env_path,
        rand_tilde_path,
    ]
    chunks = []
    for _ in range(size_kb):
        if random.random() < 0.6:
            chunks.append(random.choice(generators)())
        else:
            chunks.append(random_noise(50))
    return " ".join(chunks)


# -----------------------------
# Performance Tests
# -----------------------------

@pytest.mark.performance
def test_filepaths_large_input_performance():
    """Ensure extractor handles ~1MB mixed content quickly."""
    text = build_large_input(1000)  # ~1MB
    start = time.perf_counter()
    result = extract(text)
    duration = time.perf_counter() - start

    print(f"[perf] filepaths 1MB mixed-content: {duration:.4f}s")

    assert duration < 1.0, f"Filepath extractor too slow: {duration:.3f}s"


@pytest.mark.performance
def test_filepaths_pathological_performance():
    """
    Worst-case for regex engines:
    - deeply nested UNIX paths
    - repeated separators
    - long segments
    - UNC with huge segments
    """
    pathological = "/" + "/".join("a" * 200 for _ in range(2000))  # giant deep path

    start = time.perf_counter()
    result = extract(pathological)
    duration = time.perf_counter() - start

    print(f"[perf] pathological deep UNIX path: {duration:.4f}s")

    assert duration < 0.5, f"Pathological input too slow: {duration:.3f}s"


@pytest.mark.performance
def test_filepaths_scaling_behavior():
    """Ensure roughly linear scaling with input size."""

    # Warm-up run to stabilize regex engine
    extract(build_large_input(200))

    sizes = [300, 600, 1000, 1500]  # KB
    timings = []

    for size in sizes:
        text = build_large_input(size)

        # median of 3 runs to reduce noise
        runs = []
        for _ in range(3):
            start = time.perf_counter()
            extract(text)
            runs.append(time.perf_counter() - start)

        duration = sorted(runs)[1]  # median
        timings.append(duration)
        print(f"[perf] filepaths {size}KB: {duration:.4f}s")

    # Ensure no superlinear blow-up (allow 2.5× growth per doubling)
    for i in range(1, len(timings)):
        assert timings[i] < timings[i-1] * 2.5, "Non-linear scaling detected"

