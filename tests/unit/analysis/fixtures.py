def make_sections():
    return [
        # Suspicious section name
        {"name": ".upx", "raw_size": 100, "virtual_size": 100,
         "characteristics": 0, "entropy": 1.0},

        # High entropy
        {"name": ".rand", "raw_size": 4096, "virtual_size": 4096,
         "characteristics": 0, "entropy": 7.9},

        # Overlapping sections
        {"name": ".a", "raw_size": 100, "virtual_size": 100,
         "virtual_address": 0x1000, "entropy": 1.0},

        {"name": ".b", "raw_size": 100, "virtual_size": 100,
         "virtual_address": 0x1050, "entropy": 1.0},
    ]


def make_strings():
    return [
        "A1B2C3D4E5F6A7B8C9D0A1B2C3D4E5F6", # hex blob
        "Gur synt vf va gur qvfpbirel", # ROT13
        "normal_string",
    ]
