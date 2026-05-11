# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
import random
import string
from iocx.detectors.extractors.crypto import extract


def random_garbage(n=5000):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(alphabet) for _ in range(n))


@pytest.mark.fuzz
def test_crypto_fuzz_no_crash():
    # Run detector repeatedly on random garbage to ensure stability
    for _ in range(50):
        blob = random_garbage()
        out = extract(blob)
        assert isinstance(out, list)
        for d in out:
            assert hasattr(d, "value")
            assert hasattr(d, "category")

@pytest.mark.fuzz
def test_crypto_fuzz_embedded_valid_tokens():
    btc = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    eth = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"

    # Surround ETH with safe delimiters so regex can match it
    blob = (
        random_garbage() +
        " " + btc + " " +
        random_garbage() +
        " " + eth + " " +
        random_garbage()
    )

    out = extract(blob)
    flat = [d.value.lower() for d in out]

    assert btc.lower() in flat
    assert eth.lower() in flat
