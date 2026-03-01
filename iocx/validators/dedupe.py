def dedupe(iocs: dict):
    """
    Remove duplicate IOC values while preserving order.
    Each IOC type (domains, ips, hashes, etc.) is processed independently.
    """
    deduped = {}

    for key, values in iocs.items():
        seen = set()
        result = []

        for v in values:
            if v not in seen:
                seen.add(v)
                result.append(v)

        deduped[key] = result

    return deduped
