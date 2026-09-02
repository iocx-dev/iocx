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
import pkgutil
from typing import Dict, List, Set

import pytest

from tag_contract import check_contract

from iocx.parsers import (pe_imports, pe_relocations, pe_tls, pe_debug,
                          pe_exports, pe_delay_imports, pe_certificates, pe_exception,
                          pe_resources, pe_version_info, pe_load_config, pe_optional_header)
from iocx.validators import (imports, relocations, tls, debug,
                             exports, delay_imports, signature, exception_table,
                             resources, version_info, load_config_directory, optional_header)

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
    # Ref. _TAGLESS_PARSERS
    ("pe_load_config",     pe_load_config,     load_config_directory,{}),
    ("pe_optional_header", pe_optional_header, optional_header,      {}),
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

# Validators with no dedicated parser. Each reads the metadata and analysis
# layers directly rather than decoding structure from bytes, so there are no
# tombstone tags to drop.
_PARSERLESS_VALIDATORS: Dict[str, str] = {
    "entrypoint": (
        "Maps the entry point against sections and the overlay. Reads "
        "PublicMetadata and AnalysisDict; decodes no structure."
    ),
    "sections": (
        "Section flags, names, alignment and overlap. Reads PublicMetadata "
        "and AnalysisDict; decodes no structure."
    ),
    "rva_graph": (
        "The directory placement backbone that relocations, debug, imports "
        "and the security directory all defer to. Reads PublicMetadata and "
        "AnalysisDict; decodes no structure."
    ),
    "entropy": (
        "Computes entropy metrics over regions supplied by AnalysisDict. "
        "Decodes no structure."
    ),
}


# Parsers that legitimately emit no tombstone tags. A tagless parser passes
# the drop check vacuously, so it must be declared rather than inferred:
# otherwise a tag-extraction failure looks identical to a parser that has
# nothing to extract.
_TAGLESS_PARSERS: Set[str] = {
    # Reads two named fields from pefile's parsed OPTIONAL_HEADER with None
    # fallbacks. No byte-level decode, so no decode failure to tombstone.
    "pe_optional_header",

    # Returns a fields dict with no error list. NOTE this is a design gap
    # rather than a clean absence: four distinct conditions - no directory,
    # a malformed entry, rva == 0, and an unmapped rva - all collapse to
    # parsed_size == 0, so the validator cannot tell "absent" from
    # "declared but unreadable". Tracked separately; listed here so the
    # vacuous drop check is explicit rather than silent.
    "pe_load_config",
}


# Modules under iocx/validators that are not validators.
_NON_VALIDATOR_MODULES = {"schema", "decorators"}


def _discover_validator_modules() -> Set[str]:
    """Every validator module name in the package."""
    import iocx.validators
    return {
        name
        for _, name, _ in pkgutil.iter_modules(iocx.validators.__path__)
        if not name.startswith("_") and name not in _NON_VALIDATOR_MODULES
    }


def _paired_validator_names() -> Set[str]:
    """Validator module names covered by _PAIRS."""
    return {
        (p.values[2] if hasattr(p, "values") else p[2]).__name__.rsplit(".", 1)[-1]
        for p in _PAIRS
    }


@pytest.mark.contract
class TestContractCoverage:

    def test_every_validator_is_paired_or_exempt(self):
        """
        The registration guard. Without it, a new parser/validator pair that
        nobody adds to _PAIRS is silently unchecked - and every finding this
        contract check has produced came from a pair that WAS registered.
        """
        found = _discover_validator_modules()
        unregistered = found - _paired_validator_names() - set(_PARSERLESS_VALIDATORS)
        assert not unregistered, (
            f"validator modules in neither _PAIRS nor _PARSERLESS_VALIDATORS: "
            f"{sorted(unregistered)}. Add the pair to _PAIRS, or record why "
            f"the validator has no parser."
        )

    def test_no_stale_parserless_exemptions(self):
        """An exemption for a validator that no longer exists is misleading."""
        found = _discover_validator_modules()
        stale = set(_PARSERLESS_VALIDATORS) - found
        assert not stale, (
            f"_PARSERLESS_VALIDATORS names modules that do not exist: "
            f"{sorted(stale)}"
        )

    def test_no_stale_pairs(self):
        found = _discover_validator_modules()
        stale = _paired_validator_names() - found
        assert not stale, (
            f"_PAIRS names validator modules that do not exist: {sorted(stale)}"
        )

    def test_parserless_exemptions_carry_a_reason(self):
        """
        The reason is the point: it records WHY there is no parser, so a
        later reader can tell 'no decoder by design' from 'not built yet'.
        """
        for name, reason in _PARSERLESS_VALIDATORS.items():
            assert reason and len(reason) > 20, (
                f"{name} needs a substantive reason, not {reason!r}"
            )

    def test_a_validator_is_not_both_paired_and_exempt(self):
        overlap = _paired_validator_names() & set(_PARSERLESS_VALIDATORS)
        assert not overlap, (
            f"validators both paired and exempted: {sorted(overlap)}"
        )


@pytest.mark.contract
@pytest.mark.parametrize("name,parser_mod,validator_mod,templates",
                         _PAIRS, ids=[
                             (p.values[0] if hasattr(p, "values") else p[0])
                             for p in _PAIRS])
def test_no_parser_emits_zero_tags(name, parser_mod, validator_mod, templates):
    """
    A parser with no tags passes the drop check vacuously - emitted is
    empty, so `emitted - matched` is empty regardless of what the validator
    consumes. That is indistinguishable from a tag-extraction failure in the
    checker itself, which has happened nine times during development.

    A genuinely tagless parser must opt in via _TAGLESS_PARSERS.
    """
    if name in _TAGLESS_PARSERS:
        pytest.skip(f"{name} records no tombstone tags by design")

    import inspect
    result = check_contract(
        inspect.getsource(parser_mod),
        inspect.getsource(validator_mod),
        parser_name=name,
        validator_name=validator_mod.__name__,
        template_vars=templates,
    )
    assert result.emitted_errors or result.emitted_truncations, (
        f"{name} emitted no tags at all, so its drop check proves nothing. "
        f"Either the parser is genuinely tagless - add it to "
        f"_TAGLESS_PARSERS - or tag extraction is broken for this shape."
    )


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
