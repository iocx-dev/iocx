from iocx.detectors.extractors.crypto import extract


def test_btc_bech32_detection():
    text = "Bech32 BTC: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
    detections = extract(text)

    assert any(
        d.value == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
        and d.category == "crypto.btc"
        for d in detections
    )


def test_eth_mixed_case_checksum_detection():
    text = "Checksum ETH: 0x52908400098527886E0F7030069857D2E4169EE7"
    detections = extract(text)

    assert any(
        d.value == "0x52908400098527886E0F7030069857D2E4169EE7"
        and d.category == "crypto.eth"
        for d in detections
    )


def test_eth_lowercase_still_detected():
    text = "Lowercase ETH: 0x52908400098527886e0f7030069857d2e4169ee7"
    detections = extract(text)

    assert any(
        d.value == "0x52908400098527886e0f7030069857d2e4169ee7"
        and d.category == "crypto.eth"
        for d in detections
    )


def test_btc_and_eth_mixed_formats_together():
    text = (
        "Legacy BTC: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT "
        "Bech32 BTC: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080 "
        "ETH: 0x52908400098527886E0F7030069857D2E4169EE7"
    )
    detections = extract(text)

    values = {d.value for d in detections}

    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" in values
    assert "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080" in values
    assert "0x52908400098527886E0F7030069857D2E4169EE7" in values

