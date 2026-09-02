# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Self-tests for the tag-contract checker.

The checker is static analysis over parser/validator source, so every code
shape it must recognise is a separate case - and every shape it misread in
the past is a regression guard. Eight defects were found by feeding it real
parsers one at a time; each cost a review cycle to diagnose. These fixtures
turn that into a unit-test failure.

The fixtures are DELIBERATELY MINIMAL rather than excerpts of real parsers:
each isolates one syntactic shape, so a failure names the shape directly.

Naming conventions the checker depends on, and which it CANNOT verify:
  * a parser's module entry point is `build_<subsystem>_structure`
  * a validator's tag list is named `*_ERROR_*`, `*_TAGS` or `*_PRIORITY`
  * a per-item error list passed as a parameter is NOT named plain `errors`
Violating any of these produces a wrong verdict, not an exception, so
TestNamingConventionDependencies documents them explicitly.
"""

from __future__ import annotations

import pytest

from tag_contract import (
    check_contract,
    extract_parser_tags,
    extract_validator_consumption,
    _is_entry_point,
    _is_tag_collection,
)


# =================================================================
# Shape 1 - direct appends
# =================================================================

@pytest.mark.contract
class TestDirectAppends:

    def test_bare_name_parameter_is_top_level(self):
        src = '''
def _walk(pe, truncations, errors):
    errors.append("top_tag")
    truncations.append("trunc_tag")
'''
        tags = extract_parser_tags(src)
        assert tags.top_errors == {"top_tag"}
        assert tags.top_truncations == {"trunc_tag"}
        assert tags.item_errors == set()

    def test_bare_name_local_outside_entry_point_is_per_item(self):
        src = '''
def _decode_entry(pe, value):
    errors = []
    errors.append("item_tag")
    return {"errors": errors}
'''
        tags = extract_parser_tags(src)
        assert tags.item_errors == {"item_tag"}
        assert tags.top_errors == set()

    def test_bare_name_local_inside_entry_point_is_top_level(self):
        """
        pe_certificates creates its own lists as locals in the entry point
        and returns them as the struct's top-level errors. Same syntax as
        the per-item case above, opposite level.
        """
        src = '''
def build_certificate_structure(pe):
    errors = []
    errors.append("raw_file_unavailable")
    return {"errors": errors}
'''
        tags = extract_parser_tags(src)
        assert tags.top_errors == {"raw_file_unavailable"}
        assert tags.item_errors == set()

    def test_subscript_append_is_per_item(self):
        src = '''
def _decode(pe, descriptor):
    descriptor["errors"].append("dll_name_empty")
'''
        tags = extract_parser_tags(src)
        assert tags.item_errors == {"dll_name_empty"}

    def test_differently_named_parameter_is_per_item(self):
        """
        `descriptor_errors` is a parameter but not the canonical sink name,
        so it holds a per-descriptor list rather than the struct's own.
        """
        src = '''
def _read_thunks(pe, rva, descriptor_errors, truncations):
    descriptor_errors.append("int_rva_zero")
'''
        tags = extract_parser_tags(src)
        assert tags.item_errors == {"int_rva_zero"}
        assert tags.top_errors == set()


# =================================================================
# Shape 2 - f-string templates
# =================================================================

@pytest.mark.contract
class TestFStringTemplates:

    def test_template_expands_against_declared_values(self):
        src = '''
def _read(pe, rva, tag, truncations):
    truncations.append(f"{tag}_truncated")
'''
        tags = extract_parser_tags(src, {"tag": ["int", "iat"]})
        assert tags.top_truncations == {"int_truncated", "iat_truncated"}
        assert tags.unexpanded == set()

    def test_template_without_values_is_reported_unexpanded(self):
        """Fail loudly rather than skip - a silent skip is how the original
        drops stayed hidden."""
        src = '''
def _read(pe, rva, tag, truncations):
    truncations.append(f"{tag}_truncated")
'''
        tags = extract_parser_tags(src, {})
        assert tags.top_truncations == set()
        assert tags.unexpanded == {"f'{tag}_truncated'"}

    def test_fstring_with_no_placeholder_is_a_literal(self):
        """
        `f"literal"` stays a JoinedStr in the AST. An earlier version
        reported it as an unexpandable template.
        """
        src = '''
def _walk(pe, errors):
    errors.append(f"block_header_unpack_failed")
'''
        tags = extract_parser_tags(src)
        assert tags.top_errors == {"block_header_unpack_failed"}
        assert tags.unexpanded == set()

    def test_non_name_placeholder_is_unexpandable(self):
        src = '''
def _walk(pe, errors, index):
    errors.append(f"failed_at_{index + 1}")
'''
        tags = extract_parser_tags(src)
        assert tags.unexpanded
        assert tags.top_errors == set()


# =================================================================
# Shape 3 - helper tuple returns
# =================================================================

@pytest.mark.contract
class TestHelperTupleReturns:

    def test_tag_in_last_tuple_position(self):
        src = '''
def _read_asciiz(pe, rva, max_len):
    if rva == 0:
        return None, "rva_zero"
    return "name", None
'''
        assert extract_parser_tags(src).item_errors == {"rva_zero"}

    def test_tag_on_a_separate_line_from_return(self):
        """
        The UnicodeDecodeError shape: the literal sits on a different line
        from the `return`, which defeated regex extraction.
        """
        src = '''
def _read_asciiz(pe, rva, max_len):
    try:
        return raw.decode("ascii"), None
    except UnicodeDecodeError:
        s = raw.decode("ascii", errors="replace")
        return s, "non_ascii"
'''
        assert "non_ascii" in extract_parser_tags(src).item_errors

    def test_three_element_tuple_return(self):
        src = '''
def _read_import_by_name(pe, rva):
    return None, None, "name_too_short"
'''
        assert extract_parser_tags(src).item_errors == {"name_too_short"}


# =================================================================
# Shape 4 - literal lists in returned dicts
# =================================================================

@pytest.mark.contract
class TestDictLiteralLists:

    def test_literal_error_list_in_returned_dict(self):
        src = '''
def _decode_entry(buf, index):
    return {"index": index, "errors": ["entry_unpack_failed"]}
'''
        assert extract_parser_tags(src).item_errors == {"entry_unpack_failed"}

    def test_non_list_dict_values_do_not_raise(self):
        """
        Regression: an over-broad `for el in v.elts` ran for every dict
        value, raising AttributeError on Name and Constant nodes.
        """
        src = '''
def _decode(buf, index):
    return {"index": index, "errors": errors, "name": None,
            "count": 0, "nested": {"a": 1}}
'''
        tags = extract_parser_tags(src)   # must not raise
        assert tags.item_errors == set()

    def test_dict_with_mixed_literal_and_variable_sinks(self):
        src = '''
def _decode(buf, index):
    return {"errors": ["tag_a"], "truncations": truncations}
'''
        tags = extract_parser_tags(src)
        assert tags.item_errors == {"tag_a"}


# =================================================================
# Shape 5 - kwarg list literals
# =================================================================

@pytest.mark.contract
class TestKwargListLiterals:

    def test_kwarg_in_entry_point_is_top_level(self):
        """
        pe_exports: _empty_result builds the TOP-LEVEL struct, so a kwarg
        passed to it from the entry point fills the struct's own errors.
        """
        src = '''
def build_export_structure(pe):
    return _empty_result(rva, size, errors=["header_read_failed"])

def _empty_result(rva, size, *, errors=None, truncations=None):
    return {"errors": errors or [], "truncations": truncations or []}
'''
        tags = extract_parser_tags(src)
        assert tags.top_errors == {"header_read_failed"}
        assert tags.item_errors == set()

    def test_kwarg_outside_entry_point_is_per_item(self):
        """
        pe_exception: _unwind_result builds a PER-ENTRY record. Identical
        syntax to the case above, opposite level.
        """
        src = '''
def build_exception_structure(pe):
    return {"functions": functions}

def _decode_unwind_info(pe, rva):
    return _unwind_result(errors=["unwind_read_failed"])
'''
        tags = extract_parser_tags(src)
        assert tags.item_errors == {"unwind_read_failed"}
        assert tags.top_errors == set()

    def test_kwarg_truncations_always_top_level(self):
        src = '''
def _walk(pe):
    return _result(truncations=["table_truncated"])
'''
        assert extract_parser_tags(src).top_truncations == {"table_truncated"}


# =================================================================
# Validator consumption
# =================================================================

@pytest.mark.contract
class TestValidatorConsumption:

    def test_priority_list_recognised_by_name(self):
        src = '_ENTRY_ERROR_PRIORITY = ["a", "b"]'
        assert extract_validator_consumption(src).matched == {"a", "b"}

    @pytest.mark.parametrize("name", [
        "_DLL_NAME_ERROR_PRIORITY", "_HEADER_DECODE_ERROR_TAGS",
        "_UNWIND_ERROR_PRIORITY", "_STRUCTURAL_CERT_ERROR_TAGS",
    ])
    def test_tag_collection_names_accepted(self, name):
        assert _is_tag_collection(name)

    @pytest.mark.parametrize("name", [
        "_TABLE_ARCHS", "_VALID_UNWIND_VERSIONS", "_REVISION_NAMES",
    ])
    def test_non_tag_collection_names_rejected(self, name):
        """
        _TABLE_ARCHS = ("amd64","arm64","arm") is structurally identical to
        a priority list and produced three spurious phantoms.
        """
        assert not _is_tag_collection(name)

    def test_arch_tuple_is_not_read_as_tags(self):
        src = '''
_TABLE_ARCHS = ("amd64", "arm64", "arm")
_ENTRY_ERROR_PRIORITY = ["real_tag"]
'''
        matched = extract_validator_consumption(src).matched
        assert matched == {"real_tag"}
        assert "amd64" not in matched

    def test_membership_test_counts_as_consumption(self):
        src = '''
def _v(entry_errors):
    if "ordinal_index_duplicate" in entry_errors:
        pass
'''
        assert "ordinal_index_duplicate" in extract_validator_consumption(src).matched

    def test_iterated_wholesale_detected(self):
        src = '''
def _v(imp, issues):
    for tag in imp.get("truncations", []) or []:
        issues.append(StructuralIssue(details={"table": tag}))
'''
        assert extract_validator_consumption(src).iterated_sinks == {"truncations"}

    def test_iteration_that_ignores_the_loop_var_is_not_wholesale(self):
        """Counting a list is not forwarding it."""
        src = '''
def _v(imp, issues):
    count = 0
    for tag in imp.get("truncations", []) or []:
        count += 1
'''
        assert extract_validator_consumption(src).iterated_sinks == set()

    def test_forwarded_wholesale_detected(self):
        src = '''
def _v(imp, issues):
    issues.append(StructuralIssue(
        details={"sub_reason": "top_level_decode",
                 "errors": list(imp["errors"])}))
'''
        assert extract_validator_consumption(src).forwarded_sinks == {"errors"}

    def test_literal_details_list_is_not_forwarding(self):
        """A fixed payload names no sink."""
        src = '''
def _v(issues):
    issues.append(StructuralIssue(details={"errors": ["fixed", "payload"]}))
'''
        assert extract_validator_consumption(src).forwarded_sinks == set()


# =================================================================
# End-to-end verdicts
# =================================================================

_PARSER = '''
def build_thing_structure(pe):
    errors = []
    truncations = []
    if pe is None:
        return _empty_result(errors=["top_decode_failed"])
    errors.append("top_direct")
    truncations.append("table_truncated")
    return {"errors": errors, "truncations": truncations}

def _read_asciiz(pe, rva):
    return None, "read_failed"

def _decode_item(pe, descriptor):
    descriptor["errors"].append("item_tag")

def _decode_entry(buf, index):
    return {"index": index, "errors": ["entry_unpack_failed"]}
'''

_VALIDATOR = '''
_ITEM_ERROR_PRIORITY = ["item_tag", "read_failed", "entry_unpack_failed"]

def validate_thing(internal):
    st = internal.get("thing_struct")
    if st.get("errors"):
        issues.append(StructuralIssue(
            details={"sub_reason": "top_level_decode",
                     "errors": list(st["errors"])}))
        return issues
    for tag in st.get("truncations", []) or []:
        issues.append(StructuralIssue(details={"table": tag}))
'''

@pytest.mark.contract
class TestEndToEnd:

    def test_healthy_pair_is_clean(self):
        result = check_contract(_PARSER, _VALIDATOR)
        assert result.dropped == set()
        assert result.phantom == set()
        assert result.unexpanded == set()
        assert result.ok

    def test_dropped_item_tag_detected(self):
        bad = _VALIDATOR.replace('"item_tag", ', '')
        result = check_contract(_PARSER, bad)
        assert result.dropped == {"item_tag"}

    def test_top_level_tags_exempt_via_forwarding(self):
        """
        Both top-level tags are forwarded wholesale, so neither needs a
        priority entry. Removing the forward must expose them.
        """
        no_forward = _VALIDATOR.replace(
            '"errors": list(st["errors"])', '"count": 1')
        result = check_contract(_PARSER, no_forward)
        assert {"top_direct", "top_decode_failed"} <= result.dropped

    def test_truncations_exempt_via_iteration(self):
        result = check_contract(_PARSER, _VALIDATOR)
        assert "table_truncated" not in result.dropped

    def test_phantom_detected(self):
        bad = _VALIDATOR.replace(
            '"entry_unpack_failed"]', '"entry_unpack_failed", "never_emitted"]')
        assert check_contract(_PARSER, bad).phantom == {"never_emitted"}

    def test_report_is_readable(self):
        text = check_contract(_PARSER, _VALIDATOR, "pe_thing", "thing").report()
        assert "pe_thing -> thing" in text
        assert "OK" in text


# =================================================================
# Convention dependencies
# =================================================================

@pytest.mark.contract
class TestNamingConventionDependencies:
    """
    The checker cannot verify these conventions; it silently misclassifies
    when they are broken. Pinned so the dependency is explicit.
    """

    @pytest.mark.parametrize("name,expected", [
        ("build_import_structure", True),
        ("build_certificate_structure", True),
        ("_read_descriptors", False),
        ("build_something_else", False),
        ("make_import_structure", False),
    ])
    def test_entry_point_recognition(self, name, expected):
        import ast as _ast
        fn = _ast.parse(f"def {name}(pe): pass").body[0]
        assert _is_entry_point(fn) is expected

    def test_renamed_entry_point_misclassifies_silently(self):
        """
        A parser whose entry point is not build_*_structure has its
        top-level locals read as per-item, producing spurious drops. This
        fails as a wrong VERDICT, never as an exception.
        """
        renamed = '''
def make_thing(pe):
    errors = []
    errors.append("top_tag")
    return {"errors": errors}
'''
        tags = extract_parser_tags(renamed)
        assert tags.item_errors == {"top_tag"}    # wrong, but silent
        assert tags.top_errors == set()

    def test_unconventional_list_name_is_ignored(self):
        """A tag list named outside the convention is not read at all."""
        src = '_SOMETHING = ["real_tag"]'
        assert extract_validator_consumption(src).matched == set()


# =================================================================
# Robustness
# =================================================================

@pytest.mark.contract
class TestRobustness:

    def test_empty_source(self):
        assert extract_parser_tags("").errors == set()
        assert extract_validator_consumption("").matched == set()

    def test_source_with_no_tags(self):
        src = 'def f(x):\n    return x + 1\n'
        tags = extract_parser_tags(src)
        assert tags.errors == set() and tags.truncations == set()

    def test_nested_functions_are_walked(self):
        src = '''
def build_thing_structure(pe):
    def inner(errors):
        errors.append("nested_tag")
    return {}
'''
        assert "nested_tag" in extract_parser_tags(src).errors

    def test_append_to_unrelated_list_is_ignored(self):
        src = '''
def _walk(pe, results):
    results.append("not_a_tag")
'''
        tags = extract_parser_tags(src)
        assert tags.errors == set() and tags.truncations == set()

    def test_non_string_append_is_ignored(self):
        src = '''
def _walk(pe, errors):
    errors.append(42)
    errors.append(some_variable)
'''
        assert extract_parser_tags(src).errors == set()
