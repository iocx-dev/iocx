# Copyright (c) 2026 MalX Labs and contributors
# SPDX-License-Identifier: MPL-2.0
"""Static verification of the parser -> validator tag contract."""

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
    top_errors: Set[str] = field(default_factory=set)
    top_truncations: Set[str] = field(default_factory=set)
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
    return (isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
            and fn.name.startswith("build_")
            and fn.name.endswith("_structure"))


def _is_tag_collection(name: str) -> bool:
    upper = name.upper()
    return ("ERROR" in upper or upper.endswith("_TAGS")
            or upper.endswith("_PRIORITY"))


def _sink_ref(node: ast.AST) -> Optional[Tuple[str, bool]]:
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
    return {fn: {a.arg for a in fn.args.args}
            for fn in ast.walk(tree)
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _expand_fstring(node, template_vars):
    var = None
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
        return [prefix], None
    if var is None or var not in template_vars:
        return [], ast.unparse(node)
    return [f"{prefix}{v}{suffix}" for v in template_vars[var]], None


def extract_parser_tags(source, template_vars=None) -> ParserTags:
    template_vars = {**_DEFAULT_TEMPLATE_VARS, **(template_vars or {})}
    tree = ast.parse(source)
    out = ParserTags()
    scopes = _function_scopes(tree)

    def _bucket_for(sink, is_top):
        if sink in _TRUNCATION_SINKS:
            return out.top_truncations
        return out.top_errors if is_top else out.item_errors

    def _add(bucket, arg):
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            bucket.add(arg.value)
        elif isinstance(arg, ast.JoinedStr):
            expansions, unexpanded = _expand_fstring(arg, template_vars)
            if unexpanded is not None:
                out.unexpanded.add(unexpanded)
            else:
                bucket.update(expansions)

    for fn, params in scopes.items():
        entry_point = _is_entry_point(fn)
        for node in ast.walk(fn):
            ref = _sink_ref(node)
            if ref is not None and node.args:
                sink, is_bare = ref
                # Only the CANONICAL sink names can hold the struct's own
                # lists. A parameter called descriptor_errors / entry_errors
                # / block_errors is a per-item list passed down by its
                # owner, so it stays checkable however it is reached.
                canonical = sink in ("errors", "truncations")
                is_top = (is_bare and canonical
                          and (sink in params or entry_point))
                _add(_bucket_for(sink, is_top), node.args[0])
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg in _ALL_SINKS and isinstance(kw.value, ast.List):
                        bucket = _bucket_for(kw.arg, is_top=entry_point)
                        for el in kw.value.elts:
                            _add(bucket, el)

    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
            last = node.value.elts[-1]
            if isinstance(last, ast.Constant) and isinstance(last.value, str):
                out.item_errors.add(last.value)
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


def _iterated_sink(node):
    for sub in ast.walk(node.iter):
        if isinstance(sub, ast.Constant) and sub.value in _ALL_SINKS:
            return sub.value
    return None


def _loop_var_reaches_emission(node):
    if not isinstance(node.target, ast.Name):
        return False
    var = node.target.id
    for sub in ast.walk(node):
        if sub is node.target:
            continue
        if isinstance(sub, ast.Name) and sub.id == var and isinstance(sub.ctx, ast.Load):
            return True
    return False


def _forwarded_sinks_in_dict(node):
    found = set()
    for k, v in zip(node.keys, node.values):
        if not (isinstance(k, ast.Constant) and isinstance(k.value, str)):
            continue
        if isinstance(v, ast.List):
            continue
        for sub in ast.walk(v):
            if isinstance(sub, ast.Constant) and sub.value in _ALL_SINKS:
                found.add(sub.value)
    return found


def extract_validator_consumption(source) -> ValidatorConsumption:
    tree = ast.parse(source)
    out = ValidatorConsumption()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(
                node.value, (ast.List, ast.Set, ast.Tuple)):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if any(_is_tag_collection(n) for n in names):
                for el in node.value.elts:
                    if isinstance(el, ast.Constant) and isinstance(el.value, str):
                        out.matched.add(el.value)
        if (isinstance(node, ast.Compare) and len(node.ops) == 1
                and isinstance(node.ops[0], ast.In)
                and isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str)):
            out.matched.add(node.left.value)
        if isinstance(node, ast.For):
            sink = _iterated_sink(node)
            if sink is not None and _loop_var_reaches_emission(node):
                out.iterated_sinks.add(sink)
        if isinstance(node, ast.Dict):
            out.forwarded_sinks |= _forwarded_sinks_in_dict(node)
    return out


def check_contract(parser_source, validator_source, parser_name="parser",
                   validator_name="validator", template_vars=None) -> ContractResult:
    tags = extract_parser_tags(parser_source, template_vars)
    consumption = extract_validator_consumption(validator_source)
    unchecked = set()
    if _TRUNCATION_SINKS & consumption.wholesale_sinks:
        unchecked |= tags.top_truncations
    if _ERROR_SINKS & consumption.forwarded_sinks:
        unchecked |= tags.top_errors
    if _ERROR_SINKS & consumption.iterated_sinks:
        unchecked |= tags.errors
    checkable = (tags.errors | tags.truncations) - unchecked
    return ContractResult(
        parser=parser_name, validator=validator_name,
        emitted_errors=tags.errors, emitted_truncations=tags.truncations,
        matched=consumption.matched,
        iterated_sinks=consumption.iterated_sinks,
        forwarded_sinks=consumption.forwarded_sinks,
        dropped=checkable - consumption.matched,
        phantom=consumption.matched - tags.errors - tags.truncations,
        unexpanded=tags.unexpanded)
