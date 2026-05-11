# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import iocx.engine
import inspect
from iocx.engine import Engine


def _vals(result, category):
    return result["iocs"].get(category, [])

def test_engine_detects_btc():
    engine = Engine()
    text = "BTC: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    result = engine.extract(text)

    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" in _vals(result, "crypto.btc")

def test_engine_detects_eth():
    engine = Engine()
    text = "ETH: 0x52908400098527886E0F7030069857D2E4169EE7"
    result = engine.extract(text)

    assert "0x52908400098527886E0F7030069857D2E4169EE7" in _vals(result, "crypto.eth")

def test_engine_detects_both():
    engine = Engine()
    text = (
        "BTC: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT\n"
        "ETH: 0x52908400098527886E0F7030069857D2E4169EE7"
    )
    result = engine.extract(text)

    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" in _vals(result, "crypto.btc")
    assert "0x52908400098527886E0F7030069857D2E4169EE7" in _vals(result, "crypto.eth")
