import random
import string
import pytest

from iocx.extractors.filepaths import extract

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def rand_segment(min_len=1, max_len=12):
    chars = string.ascii_letters + string.digits + "._-"
    return "".join(random.choice(chars) for _ in range(random.randint(min_len, max_len)))

def rand_windows_path():
    drive = random.choice("CDEFGHIJKLMNOPQRSTUVWXYZ")
    dirs = "\\".join(rand_segment() for _ in range(random.randint(1, 4)))
    file = rand_segment() + random.choice([".exe", ".dll", ".txt"])
    return f"{drive}:\\{dirs}\\{file}"

def rand_unix_path():
    # require at least 2 dirs → total segments = 3
    dirs = "/".join(rand_segment() for _ in range(random.randint(2, 4)))
    file = rand_segment()
    return f"/{dirs}/{file}"

def rand_unc_path():
    server = rand_segment()
    share = rand_segment()
    dirs = [rand_segment() for _ in range(random.randint(0, 3))]
    file = rand_segment() + ".exe"

    # Build UNC path without accidental double slashes
    parts = ["\\\\", server, "\\", share]
    for d in dirs:
        parts.extend(["\\", d])
    parts.extend(["\\", file])

    return "".join(parts)

def mutate(s):
    mutations = [
        lambda x: x + random.choice(["!!!", ",,,", "???", "   "]),
        lambda x: random.choice(["prefix ", "xxx "]) + x,
        lambda x: x.replace("/", "//"),
        lambda x: x.replace("\\", "\\\\"),
        lambda x: x.replace(".", ".."),
        lambda x: x[::-1],  # reversed
    ]
    return random.choice(mutations)(s)

# ------------------------------------------------------------
# Fuzz Tests
# ------------------------------------------------------------

@pytest.mark.parametrize("generator", [
    rand_windows_path,
    rand_unix_path,
    rand_unc_path,
])
@pytest.mark.fuzz
def test_fuzz_valid_paths(generator):
    """Valid paths should always be extracted."""
    for _ in range(200):
        p = generator()
        text = f"prefix {p} suffix"
        assert p in extract(text)


@pytest.mark.parametrize("generator", [
    rand_windows_path,
    rand_unix_path,
    rand_unc_path,
])
@pytest.mark.fuzz
def test_fuzz_mutated_paths(generator):
    """Mutated paths should not cause crashes."""
    for _ in range(200):
        p = generator()
        m = mutate(p)
        extract(m)  # no crash expected

@pytest.mark.fuzz
def test_fuzz_random_noise():
    """Random noise should not produce false positives."""
    for _ in range(500):
        noise = "".join(random.choice(string.printable) for _ in range(40))

        # Skip noise that contains characters that can legitimately start a path
        if any(c in noise for c in ("/", "\\", "~", ".", "$")):
            continue

        results = extract(noise)
        assert results == []  # strict mode: no false positives
