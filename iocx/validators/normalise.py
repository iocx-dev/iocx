def normalise_iocs(iocs: dict):
    """
    Normalise IOC values by stripping whitespace,
    lowercasing where appropriate, and removing empties.
    """
    normalised = {}

    for key, values in iocs.items():
        cleaned = []

        for v in values:
            if not v:
                continue

            v = v.strip()

            # Lowercase only for types where case is irrelevant
            if key in ("domains", "emails", "urls", "filepaths"):
                v = v.lower()

            cleaned.append(v)

        normalised[key] = cleaned

    return normalised
