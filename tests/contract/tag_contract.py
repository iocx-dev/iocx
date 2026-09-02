# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0

"""
Static verification of the parser -> validator tag contract.

Parsers record structural faults as tombstone tags in `errors` and
`truncations` lists. Validators consume those tags and map them to reason
codes. A tag with no consumer is SILENTLY DROPPED: `_first_matching` returns
"unknown" and the caller continues, so the finding never reaches output.

WHY AST AND NOT REGEX
Regex extraction misses two shapes this codebase uses: a tag returned on a
UnicodeDecodeError branch where the literal sits on a different line from the
`return`, and f-string templates such as f"{tag}_truncated" which expand to
several concrete tags depending on the caller.

THREE CONSUMPTION PATTERNS
Conflating these produces false positives, so each is detected separately:

  * ITERATED WHOLESALE
        for tag in x["truncations"]:
            emit(details={"table": tag})
    Every tag becomes its own issue.

  * FORWARDED WHOLESALE
        emit(details={"sub_reason": "top_level_decode",
                      "errors": list(imp["errors"])})
    The whole list is copied into one issue's details. No tag is lost, but
    there is no loop to detect - this shape was missed by an earlier version
    of this module and produced a false positive on `descriptor_unpack_failed`.

  * PRIORITY-MATCHED
        _first_matching(errors, _SOME_PRIORITY_LIST)
    Only listed tags are emitted. This is the sink that can drop.

Only the third needs a membership check.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


_ERROR_SINKS = {"errors", "entry_errors", "descriptor_errors", "block_errors"}
_TRUNCATION_SINKS = {"truncations"}
_ALL_SINKS = _ERROR_SINKS | _TRUNCATION_SINKS

_DEFAULT_TEMPLATE_VARS: Dict[str, List[str]] = {}


@dataclass
class ParserTags:
    # Tags written to the caller-owned lists returned at the top level of
    # the struct. Identified by an append to a bare name that is a PARAMETER
    # of the enclosing function and named exactly "errors"/"truncations".
    top_errors: Set[str] = field(default_factory=set)
    top_truncations: Set[str] = field(default_factory=set)
    # Tags written to per-descriptor / per-entry lists: appends to a local,
    # to a subscript, or to a differently-named parameter such as
    # `descriptor_errors`.
    item_errors: Set[str] = field(default_factory=set)
    unexpanded: Set[str] = field(default_factory=set)

    @property
    def errors(self) -> Set[str]:
        return self.top_errors | self.item_errors

    @property
    def truncations(self) -> Set[str]:
        return self.top_truncations


@dataclass
class ValidatorConsumption:
    matched: Set[str] = field(default_factory=set)
    iterated_sinks: Set[str] = field(default_factory=set)
    forwarded_sinks: Set[str] = field(default_factory=set)

    @property
    def wholesale_sinks(self) -> Set[str]:
        return self.iterated_sinks | self.forwarded_sinks


@dataclass
class ContractResult:
    parser: str
    validator: str
    emitted_errors: Set[str]
    emitted_truncations: Set[str]
    matched: Set[str]
    iterated_sinks: Set[str]
    forwarded_sinks: Set[str]
    dropped: Set[str]
    phantom: Set[str]
    unexpanded: Set[str]

    @property
    def ok(self) -> bool:
        return not (self.dropped or self.unexpanded)

    def report(self) -> str:
        lines = [f"{self.parser} -> {self.validator}"]
        lines.append(f"  emitted (errors)      : {len(self.emitted_errors)}")
        lines.append(f"  emitted (truncations) : {len(self.emitted_truncations)}")
        lines.append(f"  iterated wholesale    : {sorted(self.iterated_sinks) or 'none'}")
        lines.append(f"  forwarded wholesale   : {sorted(self.forwarded_sinks) or 'none'}")
        if self.dropped:
            lines.append(f"  DROPPED               : {sorted(self.dropped)}")
        if self.unexpanded:
            lines.append(f"  UNEXPANDED TEMPLATES  : {sorted(self.unexpanded)}")
        if self.phantom:
            lines.append(f"  phantom (unreachable) : {sorted(self.phantom)}")
        if self.ok and not self.phantom:
            lines.append("  OK - every emittable tag has a consumer")
        return "\n".join(lines)


def _is_entry_point(fn: ast.AST) -> bool:
        """
        The function that builds the top-level struct. Every parser follows the
        build_<subsystem>_structure convention, and that function owns the
        struct's own errors/truncations lists - which it creates as locals
        rather than receiving as parameters.
        """
        return (isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
            and fn.name.startswith("build_")
            and fn.name.endswith("_structure"))


def _is_tag_collection(name: str) -> bool:
        """
        A module-level collection holds tombstone tags only if its name says so.
        Structurally, a tag priority list and an architecture set are identical,
        so the distinction has to come from the naming convention:
        *_ERROR_*, *_TAGS or *_PRIORITY.
        """
        upper = name.upper()
        return ("ERROR" in upper
            or upper.endswith("_TAGS")
            or upper.endswith("_PRIORITY"))


# =================================================================
# Parser side
# =================================================================

def _sink_ref(node: ast.AST) -> Optional[Tuple[str, bool]]:
    """
    Return (sink_name, is_bare_name) for an X.append(...) call, else None.

    is_bare_name distinguishes `errors.append(...)` from
    `descriptor["errors"].append(...)`, which the scope rule needs.
    """
    if not (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "append"):
        return None
    target = node.func.value
    if isinstance(target, ast.Name) and target.id in _ALL_SINKS:
        return (target.id, True)
    if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
        if target.slice.value in _ALL_SINKS:
            return (target.slice.value, False)
    return None


def _function_scopes(tree: ast.AST) -> Dict[ast.AST, Set[str]]:
    """Map each function node to the set of its parameter names."""
    scopes: Dict[ast.AST, Set[str]] = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes[fn] = {a.arg for a in fn.args.args}
    return scopes


def _expand_fstring(node: ast.JoinedStr,
                    template_vars: Dict[str, List[str]]) -> Tuple[List[str], Optional[str]]:
    var: Optional[str] = None
    prefix = suffix = ""
    seen_var = False
    has_placeholder = False
    for part in node.values:
        if isinstance(part, ast.FormattedValue):
            has_placeholder = True
            if isinstance(part.value, ast.Name):
                var = part.value.id
                seen_var = True
            else:
                return [], ast.unparse(node)
        elif isinstance(part, ast.Constant):
            if seen_var:
                suffix += str(part.value)
            else:
                prefix += str(part.value)
    if not has_placeholder:
        # An f-string with nothing to interpolate is a literal in disguise.
        return [prefix], None
    if var is None or var not in template_vars:
        return [], ast.unparse(node)
    return [f"{prefix}{v}{suffix}" for v in template_vars[var]], None


def extract_parser_tags(
    source: str,
    template_vars: Optional[Dict[str, List[str]]] = None,
) -> ParserTags:
    """
    Extract every tombstone tag a parser can emit.

    Five shapes are recognised, all of which occur in this codebase:
    1. sink.append("tag")
    2. sink.append(f"{var}_suffix") - expanded via template_vars
    3. return <...>, "tag" - helper readers whose tag the caller
    appends verbatim
    4. {"errors": ["tag", ...]} - literal list in a returned dict
    5. f(errors=["tag"]) - kwarg list literal passed to a
    result-builder helper

    Sinks are classified top-level vs per-item by SCOPE: a bare-name append
    is top-level when the name is a function parameter (a caller-owned list)
    or when it occurs inside the module entry point, which creates the
    struct's own lists as locals. Anything else - a local elsewhere, a
    subscript, or a differently-named parameter such as descriptor_errors -
    is per-item.
    """
    template_vars = {**_DEFAULT_TEMPLATE_VARS, **(template_vars or {})}
    tree = ast.parse(source)
    out = ParserTags()
    scopes = _function_scopes(tree)

    def _bucket_for(sink: str, is_top: bool) -> Set:
        if sink in _TRUNCATION_SINKS:
            return out.top_truncations
        return out.top_errors if is_top else out.item_errors

    def _add(bucket: Set[str], arg: ast.AST) -> None:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            bucket.add(arg.value)
        elif isinstance(arg, ast.JoinedStr):
            expansions, unexpanded = _expand_fstring(arg, template_vars)
            if unexpanded is not None:
                out.unexpanded.add(unexpanded)
            else:
                bucket.update(expansions)

    # --- Shapes 1, 2 and 5: scope-sensitive, so walked per function ---
    for fn, params in scopes.items():
        entry_point = _is_entry_point(fn)
        for node in ast.walk(fn):
            # 1 & 2 - direct appends
            ref = _sink_ref(node)
            if ref is not None and node.args:
                sink, is_bare = ref
                is_top = is_bare and (sink in params or entry_point)
                _add(_bucket_for(sink, is_top), node.args[0])

            # 5 - kwarg list literal passed to a result-builder helper.
            # The SAME entry-point rule applies as for bare-name appends:
            # _empty_result(errors=[...]) inside build_*_structure fills the
            # top-level struct, while _unwind_result(errors=[...]) in a
            # decode helper fills a per-entry record. Identical syntax,
            # opposite level.
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg in _ALL_SINKS and isinstance(kw.value, ast.List):
                        # A result-builder helper returns a per-item record.
                        bucket = _bucket_for(kw.arg, is_top=entry_point)
                        for el in kw.value.elts:
                            _add(bucket, el)

    # --- Shapes 3 and 4: scope-independent ---
    for node in ast.walk(tree):
        # 3 - helper returns whose last element is an error tag
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
            last = node.value.elts[-1]
            if isinstance(last, ast.Constant) and isinstance(last.value, str):
                # A helper's tag is appended by its caller, always per-item
                # in this codebase.
                out.item_errors.add(last.value)

        # 4 - literal tag lists inside a returned dict
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if (isinstance(k, ast.Constant) and k.value in _ALL_SINKS
                        and isinstance(v, ast.List)):
                    bucket = (out.top_truncations
                            if k.value in _TRUNCATION_SINKS
                            else out.item_errors)
                    for el in v.elts:
                        if isinstance(el, ast.Constant) and isinstance(el.value, str):
                            bucket.add(el.value)

    return out


# =================================================================
# Validator side
# =================================================================

def _iterated_sink(node: ast.For) -> Optional[str]:
    for sub in ast.walk(node.iter):
        if isinstance(sub, ast.Constant) and sub.value in _ALL_SINKS:
            return sub.value
    return None


def _loop_var_reaches_emission(node: ast.For) -> bool:
    if not isinstance(node.target, ast.Name):
        return False
    var = node.target.id
    for sub in ast.walk(node):
        if sub is node.target:
            continue
        if isinstance(sub, ast.Name) and sub.id == var and isinstance(sub.ctx, ast.Load):
            return True
    return False


def _forwarded_sinks_in_dict(node: ast.Dict) -> Set[str]:
    """
    Detect a details payload that copies a whole sink list verbatim, e.g.

        details={"errors": list(imp["errors"])}

    A LITERAL list value is a fixed payload, not forwarding, and is
    excluded. Any other expression that reads a sink name is treated as
    forwarding that sink.
    """
    found: Set[str] = set()
    for k, v in zip(node.keys, node.values):
        if not (isinstance(k, ast.Constant) and isinstance(k.value, str)):
            continue
        if isinstance(v, ast.List):
            continue          # literal payload, not a forward
        for sub in ast.walk(v):
            if isinstance(sub, ast.Constant) and sub.value in _ALL_SINKS:
                found.add(sub.value)
    return found


def extract_validator_consumption(source: str) -> ValidatorConsumption:
    """
    Extract how a validator consumes tags.

    Priority-matched: module-level collections of string literals whose NAME
    marks them as tag lists, plus explicit "tag" in &lt;errors&gt; tests.

    Wholesale: a sink forwarded in full, either by iterating it
    (for tag in x["truncations"]: emit(... tag ...)) or by copying it into
    a details payload (details={"errors": list(imp["errors"])}). Neither
    can drop a tag, so neither needs a membership check.
    """
    tree = ast.parse(source)
    out = ValidatorConsumption()

    for node in ast.walk(tree):
        # Priority lists - name-filtered. Without this, any module-level
        # tuple of strings is read as a tag list: _TABLE_ARCHS =
        # ("amd64", "arm64", "arm") produced three spurious phantoms.
        if isinstance(node, ast.Assign) and isinstance(
            node.value, (ast.List, ast.Set, ast.Tuple)):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if any(_is_tag_collection(n) for n in names):
                for el in node.value.elts:
                    if isinstance(el, ast.Constant) and isinstance(el.value, str):
                        out.matched.add(el.value)

        # Explicit membership test: "tag" in entry_errors
        if (isinstance(node, ast.Compare) and len(node.ops) == 1
            and isinstance(node.ops[0], ast.In)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)):
            out.matched.add(node.left.value)

        # Wholesale by iteration
        if isinstance(node, ast.For):
            sink = _iterated_sink(node)
            if sink is not None and _loop_var_reaches_emission(node):
                out.iterated_sinks.add(sink)

        # Wholesale by forwarding into a details payload
        if isinstance(node, ast.Dict):
            out.forwarded_sinks |= _forwarded_sinks_in_dict(node)

    return out


# =================================================================
# Comparison
# =================================================================

def check_contract(
    parser_source: str,
    validator_source: str,
    parser_name: str = "parser",
    validator_name: str = "validator",
    template_vars: Optional[Dict[str, List[str]]] = None,
) -> ContractResult:
    tags = extract_parser_tags(parser_source, template_vars)
    consumption = extract_validator_consumption(validator_source)

    # Wholesale consumption exempts ONLY the level it actually forwards.
    # The validator's `details={"errors": list(imp["errors"])}` copies the
    # TOP-LEVEL list; per-descriptor and per-entry errors remain
    # priority-matched and can still drop.
    unchecked: Set[str] = set()
    if _TRUNCATION_SINKS & consumption.wholesale_sinks:
        unchecked |= tags.top_truncations
    if _ERROR_SINKS & consumption.forwarded_sinks:
        unchecked |= tags.top_errors
    if _ERROR_SINKS & consumption.iterated_sinks:
        unchecked |= tags.errors

    checkable = (tags.errors | tags.truncations) - unchecked
    dropped = checkable - consumption.matched
    phantom = consumption.matched - tags.errors - tags.truncations

    return ContractResult(
        parser=parser_name,
        validator=validator_name,
        emitted_errors=tags.errors,
        emitted_truncations=tags.truncations,
        matched=consumption.matched,
        iterated_sinks=consumption.iterated_sinks,
        forwarded_sinks=consumption.forwarded_sinks,
        dropped=dropped,
        phantom=phantom,
        unexpanded=tags.unexpanded,
    )
