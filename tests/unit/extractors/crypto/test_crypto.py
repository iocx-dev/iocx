from iocx.detectors.extractors.crypto import extract
from iocx.models import Detection

def test_btc_detection():
    text = "Send BTC to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    detections = extract(text)

    assert any(
        d.value == "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" and d.category == "crypto.btc"
        for d in detections
    )

def test_eth_detection():
    text = "ETH: 0x52908400098527886E0F7030069857D2E4169EE7"
    detections = extract(text)

    assert any(
        d.value == "0x52908400098527886E0F7030069857D2E4169EE7" and d.category == "crypto.eth"
        for d in detections
    )

def test_no_false_positives():
    text = "This is not a crypto address."
    detections = extract(text)

    assert detections == []
