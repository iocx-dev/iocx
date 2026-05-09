# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

import pytest
from iocx.detectors.extractors.filepaths import extract

@pytest.mark.parametrize("text, expected", [
    ("/usr/bin/python3", ["/usr/bin/python3"]),
    ("/opt/my-app/run.sh", ["/opt/my-app/run.sh"]),
    ("/path/with\nnewline", ["/path/with"]),
])
def test_unix_abs_positive(text, expected):
    out = extract(text)
    assert [d.value for d in out] == expected


@pytest.mark.parametrize("text", [
    "/justslash/",        # trailing slash → directory
    "/path with space/a", # spaces not allowed
])
def test_unix_abs_negative(text):
    out = extract(text)
    assert [d.value for d in out] == []

