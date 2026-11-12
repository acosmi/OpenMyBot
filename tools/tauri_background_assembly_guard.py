#!/usr/bin/env python3
"""Structural guard for the production Desktop Local staged shutdown."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


class GuardError(ValueError):
    """Raised when the production shutdown structure is not the reviewed shape."""


TOKEN = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*|(?:0[xob])?[0-9][0-9A-Za-z_]*|"
    r"::|->|=>|&&|\|\||==|!=|<=|>=|\.\.=|\.\.|[^\s]"
)


def _blank_literals_and_comments(source: str) -> str:
    """Remove Rust comments and literals while preserving offsets and newlines."""

    chars = list(source)
    size = len(source)
    index = 0

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if chars[position] != "\n":
                chars[position] = " "

    while index < size:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = size if end < 0 else end
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < size and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise GuardError("unterminated Rust block comment")
            blank(index, end)
            index = end
            continue

        raw = re.match(r"(?:br|r)(?P<hashes>#{0,16})\"", source[index:])
        if raw:
            delimiter = '"' + raw.group("hashes")
            content_start = index + raw.end()
            end = source.find(delimiter, content_start)
            if end < 0:
                raise GuardError("unterminated Rust raw string")
            end += len(delimiter)
            blank(index, end)
            index = end
            continue

        prefix = 1 if source[index:index + 2] in {'b"', 'c"'} else 0
        if source[index + prefix:index + prefix + 1] == '"':
            end = index + prefix + 1
            escaped = False
            while end < size:
                char = source[end]
                end += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    break
            else:
                raise GuardError("unterminated Rust string")
            blank(index, end)
            index = end
            continue

        if source[index] == "'":
            # Distinguish a character literal from a Rust lifetime.
            end = index + 1
            escaped = False
            while end < min(size, index + 10):
                char = source[end]
                end += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == "'":
                    blank(index, end)
                    index = end
                    break
            else:
                index += 1
            continue
        index += 1
    return "".join(chars)


def _tokens(source: str) -> list[str]:
    return TOKEN.findall(_blank_literals_and_comments(source))


def _matches(tokens: list[str], start: int, sequence: tuple[str, ...]) -> bool:
    return tokens[start:start + len(sequence)] == list(sequence)


def _find_all(tokens: list[str], sequence: tuple[str, ...]) -> list[int]:
    return [
        index
        for index in range(0, len(tokens) - len(sequence) + 1)
        if _matches(tokens, index, sequence)
    ]


def _paired(tokens: list[str], start: int, opening: str, closing: str) -> int:
    if start >= len(tokens) or tokens[start] != opening:
        raise GuardError(f"expected {opening}")
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index] == opening:
            depth += 1
        elif tokens[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    raise GuardError(f"unclosed {opening}")


def _unique(tokens: list[str], sequence: tuple[str, ...], label: str) -> int:
    matches = _find_all(tokens, sequence)
    if len(matches) != 1:
        raise GuardError(f"expected one {label}, found {len(matches)}")
    return matches[0]


def _split_arguments(tokens: list[str]) -> list[list[str]]:
    result: list[list[str]] = []
    start = 0
    stack: list[str] = []
    pairs = {')': '(', '}': '{', ']': '['}
    for index, token in enumerate(tokens):
        if token in "({[":
            stack.append(token)
        elif token in ")}]":
            if not stack or stack.pop() != pairs[token]:
                raise GuardError("unbalanced expression")
        elif token == "," and not stack:
            result.append(tokens[start:index])
            start = index + 1
    if stack:
        raise GuardError("unbalanced expression")
    result.append(tokens[start:])
    return [argument for argument in result if argument]


def _match_arms(tokens: list[str]) -> list[tuple[tuple[str, ...], list[str]]]:
    arms: list[tuple[tuple[str, ...], list[str]]] = []
    cursor = 0
    while cursor < len(tokens):
        if tokens[cursor] == ",":
            cursor += 1
            continue
        try:
            arrow = tokens.index("=>", cursor)
        except ValueError as error:
            raise GuardError("match arm is missing =>") from error
        pattern = tuple(tokens[cursor:arrow])
        if arrow + 1 >= len(tokens) or tokens[arrow + 1] != "{":
            raise GuardError("match arm must use an explicit block")
        close = _paired(tokens, arrow + 1, "{", "}")
        arms.append((pattern, tokens[arrow + 2:close]))
        cursor = close + 1
    return arms


def _block_after(tokens: list[str], marker: tuple[str, ...], label: str) -> list[str]:
    marker_at = _unique(tokens, marker, label)
    try:
        opening = tokens.index("{", marker_at + len(marker))
    except ValueError as error:
        raise GuardError(f"{label} has no body") from error
    closing = _paired(tokens, opening, "{", "}")
    return tokens[opening + 1:closing]


def _binding(tokens: list[str], at: int) -> tuple[str, int] | None:
    """Name and `let` position of the `let NAME = …;` statement that contains token `at`."""

    for index in range(at - 1, -1, -1):
        if tokens[index] == ";":
            return None
        if tokens[index] == "let":
            cursor = index + 1
            if cursor < at and tokens[cursor] == "mut":
                cursor += 1
            if cursor < at and tokens[cursor].isidentifier() and "=" in tokens[cursor + 1:at]:
                return tokens[cursor], index
            return None
    return None


def _origin(tokens: list[str], name: str, before: int) -> tuple[str, int | None]:
    """Follow visible `let name = other;` aliases back to the `let` that introduced the value.

    Only bindings in the scope enclosing `before` count; a `let` inside an already closed block
    (dead or not) is invisible there. A macro call group (`name! { … }`, `name!( … )`,
    `name![ … ]`) is not a block: a macro may expand its tokens, nested braces included, into the
    enclosing scope, so every brace inside the group stays transparent. The position, not the
    name, identifies the value.
    """

    transparent = set()
    for index in range(1, before):
        if tokens[index - 1] == "!" and tokens[index] in {"(", "[", "{"}:
            closing = {"(": ")", "[": "]", "{": "}"}[tokens[index]]
            close = _paired(tokens, index, tokens[index], closing)
            transparent.update(i for i in range(index, close + 1) if tokens[i] in {"{", "}"})
    nested = 0
    for index in range(before - 1, -1, -1):
        if index in transparent:
            continue
        if tokens[index] == "}":
            nested += 1
            continue
        if tokens[index] == "{":
            nested = max(nested - 1, 0)
            continue
        cursor = index + 2 if tokens[index + 1:index + 2] == ["mut"] else index + 1
        if nested or tokens[index] != "let" or tokens[cursor:cursor + 1] != [name]:
            continue
        rhs = tokens[cursor + 1:cursor + 4]
        if len(rhs) == 3 and rhs[0] == "=" and rhs[1].isidentifier() and rhs[2] == ";":
            name = rhs[1]
            continue
        return name, index
    return name, None


def _conjunction(tokens: list[str]) -> list[str] | None:
    """Identifiers of a pure `a && b && …` expression, otherwise None."""

    terms = tokens[0::2]
    if not tokens or any(token != "&&" for token in tokens[1::2]):
        return None
    if len(tokens) % 2 == 0 or not all(term.isidentifier() for term in terms):
        return None
    return terms


def _simple_aliases(
    tokens: list[str], seeds: dict[str, str] | None = None, receiver: str = "self"
) -> dict[str, str]:
    aliases: dict[str, str] = dict(seeds or {})
    fields = {"lifecycle", "transport", "agent_host", "assembly", "data_plane"}
    for index, token in enumerate(tokens):
        if token == "let":
            cursor = index + 1
            if cursor < len(tokens) and tokens[cursor] == "mut":
                cursor += 1
            if cursor >= len(tokens) or not tokens[cursor].isidentifier():
                continue
            name = tokens[cursor]
            try:
                equals = tokens.index("=", cursor + 1)
                end = tokens.index(";", equals + 1)
            except ValueError:
                aliases.pop(name, None)
                continue
            rhs = tokens[equals + 1:end]
            resources = {
                rhs[pos + 2]
                for pos in range(len(rhs) - 2)
                if rhs[pos:pos + 2] == [receiver, "."] and rhs[pos + 2] in fields
            }
            if rhs == ["crate", "::", "cancel", "::", "SHUTDOWN_DEADLINE"]:
                resources.add("shared_shutdown_deadline")
            resources.update(aliases[value] for value in rhs if value in aliases)
            if len(resources) == 1:
                aliases[name] = next(iter(resources))
            else:
                aliases.pop(name, None)
        if _matches(tokens, index, ("if", "let", "Some", "(")):
            inner = index + 4
            if inner + 3 < len(tokens) and tokens[inner].isidentifier():
                close = inner + 1
                if tokens[close:close + 2] == [")", "="]:
                    outer = tokens[close + 2]
                    if outer in aliases:
                        aliases[tokens[inner]] = aliases[outer]
                    else:
                        aliases.pop(tokens[inner], None)
        if token == "match" and tokens[index + 2:index + 3] == ["{"]:
            outer = tokens[index + 1]
            if outer not in aliases:
                continue
            close = _paired(tokens, index + 2, "{", "}")
            for some_at in _find_all(tokens[index + 3:close], ("Some", "(")):
                some_at += index + 3
                pattern_close = _paired(tokens, some_at + 1, "(", ")")
                pattern = tokens[some_at + 2:pattern_close]
                if pattern[:1] == ["mut"]:
                    pattern = pattern[1:]
                if (
                    len(pattern) == 1 and pattern[0].isidentifier()
                    and tokens[pattern_close + 1:pattern_close + 2] == ["=>"]
                ):
                    aliases[pattern[0]] = aliases[outer]
    return aliases


def _value_aliases(tokens: list[str], seeds: dict[str, str]) -> dict[str, str]:
    aliases = dict(seeds)
    for index, token in enumerate(tokens):
        if token != "let" or index + 3 >= len(tokens):
            continue
        cursor = index + 1
        if tokens[cursor] == "mut":
            cursor += 1
        if not tokens[cursor].isidentifier():
            continue
        name = tokens[cursor]
        try:
            equals = tokens.index("=", cursor + 1)
            end = tokens.index(";", equals + 1)
        except ValueError:
            aliases.pop(name, None)
            continue
        rhs = tokens[equals + 1:end]
        if len(rhs) == 1 and rhs[0] in aliases:
            aliases[name] = aliases[rhs[0]]
        else:
            aliases.pop(name, None)
    return aliases


def _receiver_resource(
    tokens: list[str], method_at: int, aliases: dict[str, str], receiver: str
) -> str | None:
    if method_at >= 4 and tokens[method_at - 4:method_at] == [
        receiver,
        ".",
        tokens[method_at - 2],
        ".",
    ]:
        return tokens[method_at - 2]
    if method_at >= 2 and tokens[method_at - 1] == ".":
        return aliases.get(tokens[method_at - 2])
    return None


def _method_calls(
    tokens: list[str], method: str, aliases: dict[str, str], receiver: str
) -> list[tuple[int, str | None]]:
    return [
        (index, _receiver_resource(tokens, index, aliases, receiver))
        for index, token in enumerate(tokens)
        if token == method and index + 1 < len(tokens) and tokens[index + 1] == "("
    ]


def _call_arguments(tokens: list[str], marker: tuple[str, ...], label: str) -> list[list[str]]:
    call_at = _unique(tokens, marker, label)
    opening = call_at + len(marker) - 1
    closing = _paired(tokens, opening, "(", ")")
    return _split_arguments(tokens[opening + 1:closing])


def _brace_depths(tokens: list[str]) -> list[int]:
    depths: list[int] = []
    depth = 0
    for token in tokens:
        depths.append(depth)
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
    return depths


def _strip_parentheses(tokens: list[str]) -> list[str]:
    result = tokens
    while (
        len(result) >= 2
        and result[0] == "("
        and _paired(result, 0, "(", ")") == len(result) - 1
    ):
        result = result[1:-1]
    return result


def _check_database_arms(arm_tokens: list[str]) -> None:
    arms = _split_arguments(arm_tokens)
    if len(arms) != 2:
        raise GuardError("database owner match must retain exactly Some and None branches")

    some_seen = False
    none_seen = False
    for arm in arms:
        if "=>" not in arm:
            raise GuardError("database owner match arm is malformed")
        arrow = arm.index("=>")
        pattern = arm[:arrow]
        expression = _strip_parentheses(arm[arrow + 1:])
        if (
            len(pattern) == 4
            and pattern[:2] == ["Some", "("]
            and pattern[2].isidentifier()
            and pattern[3] == ")"
        ):
            if some_seen:
                raise GuardError("database owner match duplicated its Some branch")
            some_seen = True
            binding = pattern[2]
            expected = [
                binding,
                ".",
                "shutdown",
                "(",
                ")",
                ".",
                "await",
            ]
            if expression != expected:
                raise GuardError("database Some branch no longer returns its shutdown result")
        elif pattern == ["None"]:
            if none_seen:
                raise GuardError("database owner match duplicated its None branch")
            none_seen = True
            if expression != _tokens("""Err((
                DesktopLocalCompositionError::SidecarShutdown,
                Err(crate::postgres_sidecar::SidecarOutcome::Unknown),
                crate::desktop_local_bootstrap::SqlDriverOutcome::Unknown,
            ))"""):
                raise GuardError("database None branch must remain a failed shutdown stage")
        else:
            raise GuardError("database owner match pattern drift")
    if not some_seen or not none_seen:
        raise GuardError("database owner match lost a required branch")


@dataclass(frozen=True)
class HelperShape:
    non_database_parameter: str
    database_parameter: str
    deadline_parameter: str


def _check_helper(tokens: list[str]) -> HelperShape:
    function_at = _unique(
        tokens,
        ("async", "fn", "finish_shutdown_stages", "<"),
        "finish_shutdown_stages helper",
    )
    parameters_open = tokens.index("(", function_at + 3)
    if tokens[function_at + 3:parameters_open] != ["<", "N", ",", "D", ",", "E", ">"]:
        raise GuardError("finish_shutdown_stages original-result type parameters drift")
    parameters_close = _paired(tokens, parameters_open, "(", ")")
    parameters = []
    start, depth = parameters_open + 1, 0
    for index in range(start, parameters_close):
        if tokens[index] == "<":
            depth += 1
        elif tokens[index] == ">":
            depth -= 1
        elif tokens[index] == "," and depth == 0:
            parameters.append(tokens[start:index])
            start = index + 1
    if start < parameters_close:
        parameters.append(tokens[start:parameters_close])
    if len(parameters) != 3:
        raise GuardError("finish_shutdown_stages must retain three bounded stage parameters")
    names = []
    for parameter in parameters:
        if ":" not in parameter:
            raise GuardError("finish_shutdown_stages parameter shape drift")
        names.append(parameter[0])
    expected_types = [
        _tokens("impl Future<Output = (bool, N)>"),
        _tokens("impl Future<Output = Result<D, E>>"),
        ["Duration"],
    ]
    if [parameter[2:] for parameter in parameters] != expected_types:
        raise GuardError("finish_shutdown_stages must preserve the original stage outputs")
    shape = HelperShape(*names)
    try:
        body_open = tokens.index("{", parameters_close + 1)
    except ValueError as error:
        raise GuardError("finish_shutdown_stages has no body") from error
    body_close = _paired(tokens, body_open, "{", "}")
    body = tokens[body_open + 1:body_close]
    aliases = _simple_aliases(body, {name: name for name in names})

    timeout_at = _unique(
        body,
        ("tokio", "::", "time", "::", "timeout", "("),
        "non-database timeout",
    )
    timeout_open = timeout_at + 5
    timeout_close = _paired(body, timeout_open, "(", ")")
    timeout_arguments = _split_arguments(body[timeout_open + 1:timeout_close])
    if len(timeout_arguments) != 2:
        raise GuardError("non-database timeout argument shape drift")
    if (
        len(timeout_arguments[0]) != 1
        or aliases.get(timeout_arguments[0][0]) != shape.deadline_parameter
    ):
        raise GuardError("non-database timeout no longer uses its reviewed deadline parameter")
    if (
        len(timeout_arguments[1]) != 1
        or aliases.get(timeout_arguments[1][0]) != shape.non_database_parameter
    ):
        raise GuardError("non-database stage no longer runs inside the reviewed timeout")
    if body[timeout_close + 1:timeout_close + 3] != [".", "await"]:
        raise GuardError("non-database timeout is not awaited")
    match_open = timeout_close + 3
    if match_open >= len(body) or body[match_open] != "{":
        raise GuardError("non-database timeout must retain its closed result match")
    match_close = _paired(body, match_open, "{", "}")
    arms = _match_arms(body[match_open + 1:match_close])
    observed_arms = set()
    for pattern, arm_body in arms:
        if not arm_body:
            raise GuardError("non-database timeout match arm shape drift")
        terminal_at = max((i + 1 for i, token in enumerate(arm_body) if token == ";"), default=0)
        terminal = _split_arguments(_strip_parentheses(arm_body[terminal_at:]))
        if (
            len(pattern) == 8
            and pattern[:3] == ("Ok", "(", "(")
            and pattern[4] == ","
            and pattern[6:] == (")", ")")
            and pattern[3].isidentifier()
            and pattern[5].isidentifier()
        ):
            succeeded, original = pattern[3], pattern[5]
            if terminal != [[succeeded], ["Some", "(", original, ")"]] or any(
                _origin(arm_body, name, terminal_at) != (name, None)
                for name in (succeeded, original)
            ):
                raise GuardError("non-database timeout no longer preserves its result and observation")
            kind = "Ok"
        elif pattern == ("Err", "(", "_", ")"):
            if terminal != [["false"], ["None"]]:
                raise GuardError("non-database timeout error was projected as success or an observation")
            kind = "Err"
        else:
            raise GuardError("non-database timeout match arm shape drift")
        if kind in observed_arms:
            raise GuardError("duplicate non-database timeout match arm")
        observed_arms.add(kind)
    if observed_arms != {"Ok", "Err"}:
        raise GuardError("non-database timeout success/failure projection drift")

    database_awaits = [
        index
        for index in range(len(body) - 2)
        if body[index].isidentifier()
        and aliases.get(body[index]) == shape.database_parameter
        and body[index + 1:index + 3] == [".", "await"]
    ]
    if len(database_awaits) != 1:
        raise GuardError("database stage must be awaited exactly once")
    database_await = database_awaits[0]
    if database_await <= timeout_close:
        raise GuardError("database shutdown ran before the non-database stage completed")
    if _brace_depths(body)[database_await] != 0:
        raise GuardError("database shutdown became conditional on a prior stage")
    if any(
        token in {"return", "break", "continue", "?", "panic"}
        for token in body[:database_await]
    ):
        raise GuardError("an early exit can skip the independent database shutdown stage")

    binding_at = max(index for index in range(timeout_at) if body[index] == "let")
    if body[binding_at + 1] != "(":
        raise GuardError("non-database result and original observation tuple is missing")
    binding_close = _paired(body, binding_at + 1, "(", ")")
    bindings = _split_arguments(body[binding_at + 2:binding_close])
    if len(bindings) != 2 or any(len(part) != 1 or not part[0].isidentifier() for part in bindings):
        raise GuardError("non-database result and original observation tuple drift")
    non_database_result, original_result = (part[0] for part in bindings)
    database_value = _binding(body, database_await)
    if database_value is None:
        raise GuardError("shutdown stage result bindings are missing")
    database_projection = _unique(
        body, (database_value[0], ".", "is_ok", "(", ")"), "database result projection"
    )
    if _origin(body, database_value[0], database_projection) != database_value:
        raise GuardError("database result was replaced before its success projection")
    database_result = _binding(body, database_projection)
    if database_result is None:
        raise GuardError("database success result binding is missing")

    final_if = None
    depths = _brace_depths(body)
    for index in range(database_await + 2, len(body)):
        if body[index] == "if" and depths[index] == 0:
            try:
                candidate_open = body.index("{", index + 1)
            except ValueError:
                continue
            if "&&" in body[index + 1:candidate_open]:
                final_if = index
                break
    if final_if is None:
        raise GuardError("combined shutdown failure result is missing")
    condition_open = body.index("{", final_if + 1)
    condition = body[final_if + 1:condition_open]
    condition = _strip_parentheses(condition)
    result_aliases = _value_aliases(
        body[body.index(";", database_projection) + 1:final_if],
        {
            non_database_result: "non_database_result",
            database_result[0]: "database_result",
        },
    )
    normalized_condition = [
        result_aliases.get(token, token) if token.isidentifier() else token
        for token in condition
    ]
    if normalized_condition not in [
        ["non_database_result", "&&", "database_result"],
        ["database_result", "&&", "non_database_result"],
    ]:
        raise GuardError("shutdown success must require both stage results")
    success_close = _paired(body, condition_open, "{", "}")
    success = body[condition_open + 1:success_close]
    if success != ["Ok", "(", "(", ")", ")"]:
        raise GuardError("combined successful shutdown no longer returns Ok")
    if body[success_close + 1:success_close + 3] != ["else", "{"]:
        raise GuardError("combined shutdown failure branch is missing")
    failure_open = success_close + 2
    failure_close = _paired(body, failure_open, "{", "}")
    failure = body[failure_open + 1:failure_close]
    if failure != [
        "Err",
        "(",
        "DesktopLocalRuntimeError",
        "::",
        "Shutdown",
        ")",
    ]:
        raise GuardError("stage failure no longer returns DesktopLocalRuntimeError::Shutdown")
    outcome = _binding(body, final_if)
    returned_at = failure_close + 2
    returned = _split_arguments(_strip_parentheses(body[returned_at:]))
    if (
        outcome is None
        or body[failure_close + 1:returned_at] != [";"]
        or len(returned) != 3
        or any(len(value) != 1 for value in returned)
        or [_origin(body, value[0], returned_at) for value in returned]
        != [outcome, (original_result, None), database_value]
    ):
        raise GuardError("helper must return its outcome and both original stage observations")
    return shape


def _check_non_database_stage(non_database: list[str], aliases: dict[str, str]) -> None:
    """Four concurrent stops retain transport success and both original writer results."""

    join_at = _unique(
        non_database,
        ("tokio", "::", "join", "!", "("),
        "production non-database tokio::join",
    )
    join_open = join_at + 4
    join_close = _paired(non_database, join_open, "(", ")")
    join_arguments = _split_arguments(non_database[join_open + 1:join_close])
    if len(join_arguments) != 4:
        raise GuardError("non-database join must retain four concurrent stop branches")
    if "await" in non_database[:join_at]:
        raise GuardError("a non-database stop became serial before tokio::join")
    if (
        _find_all(non_database[:join_close], ("if", "false"))
        or _find_all(non_database[:join_close], ("if", "true"))
        or "||" in non_database[:join_close]
    ):
        raise GuardError("a concurrent stop branch is statically unreachable")
    if "data_plane" in non_database:
        raise GuardError("the data-plane owner moved into the deadline-limited non-database stage")

    expected = {
        ("transport", "shutdown"),
        ("agent_host", "stop_for_capture"),
        ("assembly", "stop_for_capture"),
        ("lifecycle", "wait_local_confirmation_stopped"),
    }
    observed: set[tuple[str, str]] = set()
    resource_arms: dict[tuple[str, str], int] = {}
    for arm_index, argument in enumerate(join_arguments):
        for method in {"shutdown", "stop_for_capture", "wait_local_confirmation_stopped"}:
            for call_at, resource in _method_calls(argument, method, aliases, "owner"):
                pair = (resource or "", method)
                if pair in expected:
                    if pair in observed:
                        raise GuardError(f"duplicate concurrent stop branch: {pair[0]}.{pair[1]}")
                    call_close = _paired(argument, call_at + 1, "(", ")")
                    if any(
                        token in {"return", "break", "continue"}
                        for token in argument[:call_at]
                    ):
                        raise GuardError(
                            f"concurrent stop is behind an early exit: {pair[0]}.{pair[1]}"
                        )
                    outer_async = argument[:2] == ["async", "{"] or argument[:3] == [
                        "async",
                        "move",
                        "{",
                    ]
                    if argument[:call_at].count("async") > int(outer_async):
                        raise GuardError(
                            f"concurrent stop is hidden in an unverified nested future: {pair[0]}.{pair[1]}"
                        )
                    awaited = argument[call_close + 1:call_close + 3] == [".", "await"]
                    direct_join_future = call_close == len(argument) - 1
                    if not awaited and not direct_join_future:
                        raise GuardError(
                            f"concurrent stop future is not polled: {pair[0]}.{pair[1]}"
                        )
                    if method == "stop_for_capture":
                        result = _binding(argument, call_at)
                        observed_at = _unique(
                            argument, ("close_observed_ns", "(", ")"), "original stop observation"
                        )
                        observed_result = _binding(argument, observed_at)
                        drop_at = _unique(
                            argument, ("drop", "(", argument[call_at - 2], ")", ";"),
                            "original stopped owner drop",
                        )
                        returned_at = _unique(argument, ("Some", "(", "("), "original stop results")
                        returned_close = _paired(argument, returned_at + 2, "(", ")")
                        returned = _split_arguments(argument[returned_at + 3:returned_close])
                        if (
                            result is None or observed_result is None
                            or not call_close < observed_at < drop_at < returned_at
                            or len(returned) != (3 if resource == "agent_host" else 2)
                            or any(len(value) != 1 for value in returned[-2:])
                            or [_origin(argument, value[0], returned_at) for value in returned[-2:]]
                            != [result, observed_result]
                        ):
                            raise GuardError("stop results must retain the original observation after owner drop")
                    observed.add(pair)
                    resource_arms[pair] = arm_index
    if observed != expected:
        missing = sorted(f"{resource}.{method}" for resource, method in expected - observed)
        raise GuardError("concurrent shutdown branch missing: " + ", ".join(missing))

    equals = None
    for index in range(join_at - 1, -1, -1):
        if non_database[index] == "=":
            equals = index
            break
    let_at = None
    if equals is not None:
        for index in range(equals - 1, -1, -1):
            if non_database[index] == "let":
                let_at = index
                break
    if equals is None or let_at is None or non_database[let_at + 1] != "(":
        raise GuardError("tokio::join result tuple binding is missing")
    pattern_close = _paired(non_database, let_at + 1, "(", ")")
    if pattern_close >= equals:
        raise GuardError("tokio::join result tuple binding is malformed")
    result_patterns = _split_arguments(non_database[let_at + 2:pattern_close])
    if len(result_patterns) != len(join_arguments):
        raise GuardError("tokio::join result tuple no longer matches its branches")
    transport_pattern = result_patterns[resource_arms[("transport", "shutdown")]]
    if len(transport_pattern) != 1 or not transport_pattern[0].isidentifier():
        raise GuardError("transport shutdown result is no longer retained")
    transport_result = transport_pattern[0]
    after_join = non_database[join_close + 1:]
    final_start = max(
        (index + 1 for index, token in enumerate(after_join) if token == ";"),
        default=0,
    )
    transport_value = [transport_result, ".", "within_deadline"]
    returned = _split_arguments(_strip_parentheses(after_join[final_start:]))
    if len(returned) != 3:
        raise GuardError("non-database stage must return transport and both original writer results")
    for value, resource in zip(returned[1:], ("agent_host", "assembly")):
        pattern = result_patterns[resource_arms[(resource, "stop_for_capture")]]
        if (
            len(pattern) != 1 or not pattern[0].isidentifier() or len(value) != 1
            or _origin(after_join, value[0], final_start) != (pattern[0], None)
        ):
            raise GuardError("the original writer stop result was discarded or replaced")
    final = _strip_parentheses(returned[0])
    used_at = final_start
    if len(final) == 1:
        origin, let_at = _origin(after_join, final[0], final_start)
        if let_at is not None and _matches(
            after_join, let_at, ("let", origin, "=", *transport_value, ";")
        ):
            final, used_at = transport_value, let_at
    if final != transport_value or _origin(after_join, transport_result, used_at) != (
        transport_result,
        None,
    ):
        raise GuardError("the transport deadline result no longer gates non-database success")


# `#[cfg(all(feature = "…", feature = "…", target_os = "…"))]` after literal blanking: the
# armed normal-exit capture gate (desktop-launcher, postgres-maintenance, macOS).
CAPTURE_CFG = (
    "#", "[", "cfg", "(", "all", "(", "feature", "=", ",", "feature", "=", ",",
    "target_os", "=", ")", ")", "]",
)
CAPTURE_BRANCH = (
    *CAPTURE_CFG, "if", "let", "Some", "(", "ready", ")", "=",
    "job", ".", "normal_ready", ".", "take", "(", ")", "{",
)


def _without_capture_branch(run: list[str]) -> list[str]:
    """Remove the one cfg-gated armed capture branch that precedes the ordinary staged path.

    The branch must be the first statement, hand the original job to the reviewed capture entry
    exactly once and end the job itself; the ordinary path after it is checked unchanged.
    """

    if not _matches(run, 0, CAPTURE_BRANCH):
        raise GuardError("armed capture branch is not the first cfg-gated job statement")
    close = _paired(run, len(CAPTURE_BRANCH) - 1, "{", "}")
    branch = run[len(CAPTURE_BRANCH):close]
    entry = (
        "capture", "::", "run_normal_exit_capture", "(", "&", "mut", "job", ",", "ready", ")",
    )
    if len(_find_all(branch, entry)) != 1 or branch[-2:] != ["return", ";"]:
        raise GuardError("armed capture branch no longer owns the job through one capture entry")
    receipt_at = _unique(branch, ("close_local_recovery", "("), "capture recovery receipt")
    receipt_close = _paired(branch, receipt_at + 1, "(", ")")
    finish_at = _unique(branch, ("job", ".", "completion", ".", "finish", "("), "capture completion")
    if (
        not _find_all(branch, entry)[0] < receipt_at < finish_at
        or _brace_depths(branch)[receipt_at] != 0
        or branch[receipt_close + 1:receipt_close + 3] != [".", "await"]
    ):
        raise GuardError("capture receipt must follow completed capture and precede completion")
    return run[close + 1:]


def _check_owner_closing(tokens: list[str]) -> None:
    """The production owner hands itself to one spawned, staged closing job."""

    implementation = _block_after(
        tokens,
        ("impl", "RuntimeShutdownOwner", "for", "DesktopLocalBackgroundOwner"),
        "production DesktopLocalBackgroundOwner RuntimeShutdownOwner impl",
    )
    start_closing = _block_after(
        implementation,
        ("fn", "start_closing", "("),
        "production DesktopLocalBackgroundOwner::start_closing",
    )
    if (
        start_closing[:2] != ["start_owned_local_closing_job", "("]
        or _paired(start_closing, 1, "(", ")") != len(start_closing) - 1
        or [argument[:1] for argument in _split_arguments(start_closing[2:-1])]
        != [["self"], ["completion"]]
    ):
        raise GuardError("production owner no longer hands itself to the owned closing job")

    # Starter: shared deadline, unconditional checked authority revocation, then one spawn.
    start = _block_after(
        tokens, ("fn", "start_owned_local_closing_job", "("), "owned closing job starter"
    )
    start_depths = _brace_depths(start)
    started_at = _unique(
        start, ("let", "started", "=", "Instant", "::", "now", "(", ")", ";"), "closing start"
    )
    deadline_at = _unique(
        start,
        ("let", "deadline", "=", "started", "+", "crate", "::", "cancel", "::",
         "SHUTDOWN_DEADLINE", ";"),
        "shared shutdown deadline",
    )
    if (
        start_depths[started_at] != 0
        or start_depths[deadline_at] != 0
        or _origin(start, "started", deadline_at) != ("started", started_at)
    ):
        raise GuardError("owned closing job lost the shared shutdown deadline")
    authority_calls = [
        index
        for index, resource in _method_calls(
            start, "shutdown_authority", _simple_aliases(start, receiver="owner"), "owner"
        )
        if resource == "lifecycle"
    ]
    if len(authority_calls) != 1:
        raise GuardError("authority must be revoked exactly once before concurrent shutdown")
    authority_call = authority_calls[0]
    if start_depths[authority_call] != 0:
        raise GuardError("authority revocation became conditional")
    authority_close = _paired(start, authority_call + 1, "(", ")")
    if start[authority_close + 1:authority_close + 5] != [".", "is_ok", "(", ")"]:
        raise GuardError("authority revocation result is no longer checked")
    authority_binding = _binding(start, authority_call)
    if authority_binding is None:
        raise GuardError("authority revocation result binding is missing")
    # Only an armed normal-exit capture skips revocation; it persists Intent first and its own
    # job revokes nothing else. Without the capture gate the flag is the literal false.
    authority_statement = start[authority_binding[1]:start.index(";", authority_call) + 1]
    capturing_flags = [
        start[max(at for at in range(index) if start[at] == "#"):start.index(";", index) + 1]
        for index in _find_all(start, ("let", "capturing", "="))
    ]
    if authority_statement[3:5] != ["capturing", "||"] or capturing_flags != [
        [*CAPTURE_CFG, "let", "capturing", "=", "normal_ready", ".", "is_some", "(", ")", "&&",
         "owner", ".", "capture_armed", ".", "is_some", "(", ")", ";"],
        ["#", "[", "cfg", "(", "not", *CAPTURE_CFG[3:-1], ")", "]",
         "let", "capturing", "=", "false", ";"],
    ]:
        raise GuardError("authority revocation is skipped outside the armed capture gate")
    spawn_at = _unique(
        start, ("spawn", "(", "run_owned_local_closing_job", "("), "owned closing job spawn"
    )
    if start_depths[spawn_at] != 0 or spawn_at < authority_call:
        raise GuardError("owned closing job is not spawned once after authority revocation")
    spawned = _call_arguments(
        start, ("run_owned_local_closing_job", "("), "owned closing job spawn argument"
    )
    literal_at = _unique(start, ("DesktopLocalClosingJob", "{"), "owned closing job literal")
    job_binding = _binding(start, literal_at)
    if len(spawned) != 1 or job_binding is None or spawned[0] != [job_binding[0]]:
        raise GuardError("spawned closing job is not the reviewed owner literal")
    literal_close = _paired(start, literal_at + 1, "{", "}")
    fields = {
        (field[0] if len(field) > 1 and field[1] == ":" else field[-1]): (
            field[2:] if len(field) > 1 and field[1] == ":" else field
        )
        for field in _split_arguments(start[literal_at + 2:literal_close])
    }
    deadline_field = fields.get("deadline", [])
    if (
        fields.get("owner") != ["Some", "(", "owner", ")"]
        or len(deadline_field) != 1
        or _origin(start, deadline_field[0], literal_at) != ("deadline", deadline_at)
    ):
        raise GuardError("owned closing job no longer carries the owner and shared deadline")
    if authority_binding not in {
        _origin(start, term, literal_at)
        for term in _conjunction(fields.get("startup_ok", [])) or []
    }:
        raise GuardError("authority revocation result no longer gates shutdown success")

    # Job: deadline-bounded non-database stage, then the independent database stage.
    run = _without_capture_branch(
        _block_after(
            tokens, ("async", "fn", "run_owned_local_closing_job", "("), "owned closing job"
        )
    )
    depths = _brace_depths(run)
    pattern_at = _unique(run, ("let", "DesktopLocalClosingJob", "{"), "owned job destructuring")
    pattern_close = _paired(run, pattern_at + 2, "{", "}")
    bound = {field[-1] for field in _split_arguments(run[pattern_at + 3:pattern_close])}
    if not {"owner", "deadline", "startup_ok", "completion", "reply"} <= bound:
        raise GuardError("owned closing job no longer destructures its reviewed fields")
    aliases = _simple_aliases(run, receiver="owner")

    timeout_at = _unique(
        run, ("tokio", "::", "time", "::", "timeout_at", "("), "non-database timeout"
    )
    timeout_close = _paired(run, timeout_at + 5, "(", ")")
    timeout_arguments = _split_arguments(run[timeout_at + 6:timeout_close])
    if (
        len(timeout_arguments) != 2
        or timeout_arguments[0][:8]
        != ["tokio", "::", "time", "::", "Instant", "::", "from_std", "("]
        or len(timeout_arguments[0]) != 10
        or timeout_arguments[0][9] != ")"
        or _origin(run, timeout_arguments[0][8], timeout_at) != ("deadline", None)
    ):
        raise GuardError("non-database timeout no longer uses the shared closing deadline")
    stage, stage_at = (
        _origin(run, timeout_arguments[1][0], timeout_at)
        if len(timeout_arguments[1]) == 1
        else ("", None)
    )
    if stage_at is None or depths[stage_at] != 0 or run[stage_at + 1:stage_at + 4] != [
        stage, "=", "async",
    ]:
        raise GuardError("non-database stage no longer runs inside the reviewed timeout")
    stage_open = stage_at + 5 if run[stage_at + 4] == "move" else stage_at + 4
    if run[stage_open] != "{":
        raise GuardError("non-database stage no longer runs inside the reviewed timeout")
    _check_non_database_stage(
        run[stage_open + 1:_paired(run, stage_open, "{", "}")], aliases
    )

    joins = [
        index
        for index in _find_all(run, ("tokio", "::", "join", "!", "("))
        if depths[index] == 0
    ]
    if len(joins) != 1:
        raise GuardError("non-database timeout must be polled by one top-level join")
    join_open = joins[0] + 4
    join_close = _paired(run, join_open, "(", ")")
    if _split_arguments(run[join_open + 1:join_close])[0] != run[timeout_at:timeout_close + 1]:
        raise GuardError("non-database timeout is not polled by the top-level join")
    let_at = max(index for index in range(joins[0]) if run[index] == "let")
    if run[let_at + 1] != "(" or not run[let_at + 2].isidentifier() or run[let_at + 3] != ",":
        raise GuardError("non-database timeout result is not retained")
    timeout_result = run[let_at + 2]
    match_at = _unique(run, ("match", "&", timeout_result, "{"), "non-database timeout match")
    if depths[match_at] != 0:
        raise GuardError("non-database timeout projection left the top-level scope")
    if any(
        run[index] == "let"
        and run[index + 2 if run[index + 1] == "mut" else index + 1] == timeout_result
        for index in range(let_at + 1, match_at)
    ):
        raise GuardError("non-database timeout result is rebound before its projection")
    match_close = _paired(run, match_at + 3, "{", "}")
    observed_arms: dict[tuple[str, ...], str] = {}
    for pattern, arm_body in _match_arms(run[match_at + 4:match_close]):
        if not arm_body or pattern in observed_arms:
            raise GuardError("non-database timeout match arm shape drift")
        observed_arms[pattern] = arm_body[-1]
    if observed_arms != {
        ("Ok", "(", "(", "true", ",", "..", ")", ")"): "true",
        ("Ok", "(", "(", "false", ",", "..", ")", ")"): "false",
        ("Err", "(", "_", ")"): "false",
    }:
        raise GuardError("non-database timeout success/failure projection drift")
    non_database_ok = _binding(run, match_at)

    plane = ("owner", ".", "data_plane", ".", "take", "(", ")")
    database_matches = []
    for index, token in enumerate(run):
        if token != "match" or depths[index] != 0:
            continue
        scrutinee = _strip_parentheses(run[index + 1:run.index("{", index + 1)])
        if len(scrutinee) == 1:
            origin, let_at = _origin(run, scrutinee[0], index)
            if let_at is None or not _matches(run, let_at, ("let", origin, "=", *plane, ";")):
                continue
        elif tuple(scrutinee) != plane:
            continue
        database_matches.append(index)
    if len(database_matches) != 1:
        raise GuardError("database stage must retain one top-level data-plane owner match")
    database_at = database_matches[0]
    if database_at <= join_close:
        raise GuardError("database shutdown ran before the non-database stage completed")
    if depths[database_at] != 0:
        raise GuardError("database shutdown became conditional on a prior stage")
    if any(token in {"return", "break", "continue", "?", "panic"} for token in run[:database_at]):
        raise GuardError("an early exit can skip the independent database shutdown stage")
    database_open = run.index("{", database_at + 1)
    database_close = _paired(run, database_open, "{", "}")
    _check_database_arms(run[database_open + 1:database_close])
    database_result = _binding(run, database_at)
    if database_result is None:
        raise GuardError("the original database shutdown result is not retained")
    database_projection = _unique(
        run, (database_result[0], ".", "is_ok", "(", ")"), "database success projection"
    )
    if (
        depths[database_projection] != 0
        or _origin(run, database_result[0], database_projection) != database_result
    ):
        raise GuardError("database success no longer comes from its original shutdown result")
    database_ok = _binding(run, database_projection)

    finish_at = _unique(run, ("completion", ".", "finish", "("), "shutdown completion")
    receipt_scope = _unique(
        run, (*_tokens('#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]'), "{"),
        "ordinary recovery receipt scope",
    )
    receipt_open = run.index("{", receipt_scope)
    receipt_end = _paired(run, receipt_open, "{", "}")
    receipt_at = _unique(run, ("close_local_recovery", "("), "ordinary recovery receipt")
    receipt_close = _paired(run, receipt_at + 1, "(", ")")
    receipt_arguments = _split_arguments(run[receipt_at + 2:receipt_close])
    if (
        not database_close < receipt_open < receipt_at < receipt_end < finish_at
        or depths[receipt_at] != 1
        or run[receipt_close + 1:receipt_close + 3] != [".", "await"]
        or len(receipt_arguments) != 5
        or receipt_arguments[0] != ["&", "mut", "owner", ".", "recovery_runtime"]
        or len(receipt_arguments[4]) != 1
        or _origin(run, receipt_arguments[4][0], receipt_at) != ("deadline", None)
    ):
        raise GuardError("recovery receipt must follow database shutdown before completion on the original deadline")
    original_at = _unique(
        run[receipt_open:receipt_end], ("match", database_result[0], "{"),
        "original database result for recovery receipt",
    ) + receipt_open
    if _origin(run, database_result[0], original_at) != database_result:
        raise GuardError("recovery receipt no longer consumes the original database shutdown result")
    receipt_helper = _block_after(
        tokens, ("async", "fn", "close_local_recovery", "("), "Local recovery receipt helper"
    )
    close_at = _unique(receipt_helper, ("close_before", "("), "runtime close_before")
    close_end = _paired(receipt_helper, close_at + 1, "(", ")")
    if receipt_helper[close_end + 1:close_end + 3] != [".", "await"]:
        raise GuardError("the runtime close receipt must be awaited")
    finish = _call_arguments(run, ("completion", ".", "finish", "("), "shutdown completion")
    terms = _conjunction(finish[0]) if len(finish) == 1 else None
    if terms is None or not {("startup_ok", None), non_database_ok, database_ok} <= {
        _origin(run, term, finish_at) for term in terms
    }:
        raise GuardError("shutdown success must require every stage result")
    succeeded = (_binding(run, finish_at) or ("", 0))[0]
    reply = _call_arguments(run, ("reply", ".", "send", "("), "shutdown reply")
    if not succeeded or reply != [[
        "if", succeeded, "{", "Ok", "(", "(", ")", ")", "}",
        "else", "{", "Err", "(", "DesktopLocalRuntimeError", "::", "Shutdown", ")", "}",
    ]]:
        raise GuardError("stage failure no longer returns DesktopLocalRuntimeError::Shutdown")

    completion_impl = _block_after(
        tokens, ("impl", "ShutdownCompletion"), "ShutdownCompletion impl"
    )
    completion_finish = _block_after(
        completion_impl, ("fn", "finish", "("), "ShutdownCompletion::finish"
    )
    if completion_finish[-1:] != ["succeeded"] or any(
        completion_finish[index + 3:completion_finish.index(";", index)][:2]
        != ["succeeded", "&&"]
        or len(completion_finish[index + 3:completion_finish.index(";", index)]) != 3
        for index in _find_all(completion_finish, ("let", "succeeded", "="))
    ):
        raise GuardError("shutdown completion can widen a failed stage result")


def check_source(source: str) -> None:
    tokens = _tokens(source)
    # Startup-failure cleanup still stages through the reviewed helper.
    helper = _check_helper(tokens)
    if helper.non_database_parameter == helper.database_parameter:
        raise GuardError("finish_shutdown_stages stage parameters collapsed")
    _check_owner_closing(tokens)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: tauri_background_assembly_guard.py <tauri_background.rs>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    try:
        source = path.read_text(encoding="utf-8")
        check_source(source)
    except (OSError, UnicodeError, GuardError) as error:
        print(f"Tauri background assembly guard: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
