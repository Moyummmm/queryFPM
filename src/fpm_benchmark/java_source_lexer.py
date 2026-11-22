"""Offset-preserving Java lexer used by the optional TP structural gate.

Pure source parsing only; no model, query, or experiment entry point.
"""
from __future__ import annotations

class InputControlError(ValueError):
    pass


def _java_units(source: str) -> list[tuple[str, int, int]]:
    """JLS Unicode-escape translation with original source-span mapping.

    Backslash eligibility uses translated trailing backslashes and whether the
    preceding unit came from an escape. Translation is not recursive.
    """
    units = []
    i = 0
    slash_run = 0
    last_escaped = False
    while i < len(source):
        start = i
        char = source[i]
        escaped = False
        if char == "\\" and (last_escaped or slash_run % 2 == 0):
            j = i + 1
            while j < len(source) and source[j] == "u":
                j += 1
            if j > i + 1:
                digits = source[j:j + 4]
                if len(digits) != 4 or not all(c in "0123456789abcdefABCDEF" for c in digits):
                    raise InputControlError("Malformed eligible Java Unicode escape")
                char = chr(int(digits, 16))
                i = j + 4
                escaped = True
        if not escaped:
            i += 1
        units.append((char, start, i))
        slash_run = slash_run + 1 if char == "\\" else 0
        last_escaped = escaped
    return units


def mask_java_comments(source: str) -> str:
    """Blank Java comments while preserving every raw newline and character offset.

    Strings, character literals, text blocks, and escapes are preserved byte for
    byte in the Python string. A fragment starts in Java CODE state; use a source
    resolver for located fragments that can begin within a multiline construct.
    """
    units = _java_units(source)
    output = list(source)
    state = "code"
    i = 0

    def at(pos: int) -> str:
        return units[pos][0] if pos < len(units) else ""

    def blank(pos: int) -> None:
        _, start, end = units[pos]
        for offset in range(start, end):
            if output[offset] not in "\r\n":
                output[offset] = " "

    while i < len(units):
        char = at(i)
        following = at(i + 1)
        if state == "code":
            if char == "/" and following in {"/", "*"}:
                state = "line" if following == "/" else "block"
                blank(i)
                blank(i + 1)
                i += 2
                continue
            if char == '"' and following == '"' and at(i + 2) == '"':
                state = "textblock"
                i += 3
                continue
            if char in {'"', "'"}:
                state = "string" if char == '"' else "char"
        elif state == "line":
            if char in "\r\n":
                state = "code"
            else:
                blank(i)
        elif state == "block":
            if char == "*" and following == "/":
                blank(i)
                blank(i + 1)
                state = "code"
                i += 2
                continue
            if char not in "\r\n":
                blank(i)
        elif state == "textblock":
            if char == "\\":
                i += 2
                continue
            if char == '"' and following == '"' and at(i + 2) == '"':
                state = "code"
                i += 3
                continue
        else:
            if char == "\\":
                i += 2
                continue
            if (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
        i += 1
    return "".join(output)
