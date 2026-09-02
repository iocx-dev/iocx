# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
CI guard: every tombstone tag a parser can emit must have a validator that
consumes it.

Add a (parser, validator, template_vars) row to _PAIRS for each subsystem.
The `template_vars` mapping supplies the call-site values for f-string tag
templates - a parser that builds f"{tag}_truncated" needs its `tag` values
listed, or the check fails loudly rather than silently skipping them.
"""

from __future__ import annotations

import inspect
from typing import Dict, List

import pytest

from tag_contract import check_contract

from iocx.parsers import (pe_imports, pe_relocations, pe_tls, pe_debug,
                          pe_exports, pe_delay_imports, pe_certificates, pe_exception,
                          pe_resources, pe_version_info)
from iocx.validators import (imports, relocations, tls, debug,
                             exports, delay_imports, signature, exception_table,
                             resources, version_info)

_PAIRS = [
    # (label, parser module, validator module, template_vars)
    #
    # template_vars supplies the call-site values for f-string tag templates.
    # pe_imports builds thunk-array tags as f"{tag}_truncated" etc., where
    # `tag` is _read_thunk_array's parameter. It is passed exactly two
    # values, from _enrich_descriptor's name-source selection:
    # "int" - OriginalFirstThunk present (normal)
    # "iat_fallback" - OriginalFirstThunk zero, fell back to FirstThunk
    # Both must be listed, or those eight tags are silently unchecked.
    ("pe_imports",         pe_imports,         imports,              {"tag": ["int", "iat_fallback"]}),
    ("pe_relocations",     pe_relocations,     relocations,          {}),
    ("pe_tls",             pe_tls,             tls,                  {}),
    ("pe_debug",           pe_debug,           debug,                {}),
    ("pe_exports",         pe_exports,         exports,              {"tag": ["eat", "enpt", "eot"]}),
    ("pe_delay_imports",   pe_delay_imports,   delay_imports,        {"tag": ["int", "iat"]}),
    ("pe_certificates",    pe_certificates,    signature,            {}),
    ("pe_exception",       pe_exception,       exception_table,      {}),
    ("pe_resources",       pe_resources,       resources,            {}),
    ("pe_version_info",    pe_version_info,    version_info,         {}),
]

# Tags a parser emits that no validator consumes, deliberately.
# Scoped per-tag so a SECOND drop in the same subsystem still fails.
_KNOWN_DELIBERATE_DROPS = {
    # pe_tls records this, but validate_tls derives TLS_INVALID_RANGE from
    # the start/end VA fields directly - more authoritative than a derived
    # tag. Redundant signalling, not a lost finding.
    "pe_tls": {"tls_raw_data_end_before_start"},
    # validate_signature checks cert["revision"] and cert["cert_type"]
    # against the known-value sets directly rather than consuming these
    # tags. The facts reach output as SIGNATURE_INVALID_REVISION /
    # SIGNATURE_INVALID_TYPE. Redundant signalling, not a lost finding.
    "pe_certificates": {"unknown_revision", "unknown_cert_type", "length_too_small"},
}

@pytest.mark.contract
@pytest.mark.parametrize("name,parser_mod,validator_mod,templates",
                         _PAIRS, ids=[p[0] for p in _PAIRS] or None)
def test_no_tag_is_silently_dropped(name, parser_mod, validator_mod, templates):
    """
    A tag with no consumer vanishes: _first_matching returns "unknown" and
    the caller continues, so the structural finding never reaches output.
    """
    result = check_contract(
        inspect.getsource(parser_mod),
        inspect.getsource(validator_mod),
        parser_name=name,
        validator_name=validator_mod.__name__,
        template_vars=templates,
    )
    unexpected = result.dropped - _KNOWN_DELIBERATE_DROPS.get(name, set())
    assert not unexpected, (
        f"\n{result.report()}\n\n"
        f"These tags are emitted by {name} but consumed by nothing. Add them "
        f"to the relevant priority list, or remove them from the parser."
    )


@pytest.mark.contract
@pytest.mark.parametrize("name,parser_mod,validator_mod,templates",
                         _PAIRS, ids=[p[0] for p in _PAIRS] or None)
def test_no_unexpandable_tag_template(name, parser_mod, validator_mod, templates):
    """
    An f-string tag whose variable has no declared expansion cannot be
    checked. Fail rather than skip - a silent skip is how the original bugs
    stayed hidden.
    """
    result = check_contract(
        inspect.getsource(parser_mod),
        inspect.getsource(validator_mod),
        parser_name=name,
        validator_name=validator_mod.__name__,
        template_vars=templates,
    )
    assert not result.unexpanded, (
        f"\n{result.report()}\n\n"
        f"Add the call-site values for these templates to _PAIRS."
    )


@pytest.mark.contract
@pytest.mark.parametrize("name,parser_mod,validator_mod,templates",
                         _PAIRS, ids=[p[0] for p in _PAIRS] or None)
def test_no_phantom_tags(name, parser_mod, validator_mod, templates):
    """
    A tag named in a priority list that no parser can produce is inert but
    misleading: it implies a routing that does not exist, and would produce
    a wrong sub_reason if the name were ever reused at another level.

    Mark xfail rather than fail if you keep deliberate defensive entries.
    """
    result = check_contract(
        inspect.getsource(parser_mod),
        inspect.getsource(validator_mod),
        parser_name=name,
        validator_name=validator_mod.__name__,
        template_vars=templates,
    )
    assert not result.phantom, (
        f"\n{result.report()}\n\n"
        f"These tags appear in a priority list but cannot be emitted."
    )
