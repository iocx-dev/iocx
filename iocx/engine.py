from .parsers.pe_parser import parse_pe
from .parsers.string_extractor import extract_strings
from .extractors import urls, domains, ips, hashes, emails, filepaths
from .validators.normalise import normalise_iocs
from .validators.dedupe import dedupe

def extract_iocs(input_data):
    # Detect whether input is a file path or raw text
    try:
        with open(input_data, "rb") as f:
            data = f.read()
        strings = extract_strings(input_data)
        text = "\n".join(strings)
        pe_meta = parse_pe(input_data)
    except Exception:
        text = input_data
        pe_meta = {}

    detected = {
        "urls": urls.extract(text),
        "domains": domains.extract(text),
        "ips": ips.extract(text),
        "hashes": hashes.extract(text),
        "emails": emails.extract(text),
        "filepaths": filepaths.extract(text),
    }

    detected = normalise_iocs(detected)
    detected = dedupe(detected)

    return {
        "iocs": detected,
        "metadata": pe_meta
    }
