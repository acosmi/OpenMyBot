#!/usr/bin/env python3
"""Find constructor owners without mistaking cfg(test) modules for production."""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True
from tauri_background_assembly_guard import GuardError, _blank_literals_and_comments


MODULE = re.compile(
    r"(?P<attrs>(?:#\s*\[[^\]]*\]\s*)*)"
    r"(?:pub(?:\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<end>[;{])"
)
CFG = re.compile(r"#\s*\[\s*cfg\s*\((?P<predicate>[^\]]*)\)\s*\]")
ALL = re.compile(r"all\s*\((?P<members>.*)\)", re.DOTALL)
PATH_ATTRIBUTE = re.compile(r'#\s*\[\s*path\s*=\s*"([^"\\]+)"\s*\]')
CONSTRUCTOR = re.compile(r"\bOpenBotApplication\s*::\s*new\b")


def _test_only(attrs: str) -> bool:
    """`#[cfg(test)]` or `#[cfg(all(…, test, …))]`; `any(…)` and `not(…)` never qualify."""

    for attribute in CFG.finditer(attrs):
        predicate = attribute.group("predicate").strip()
        if predicate == "test":
            return True
        members = ALL.fullmatch(predicate)
        if not members:
            continue
        depth, start, text = 0, 0, members.group("members") + ","
        for index, char in enumerate(text):
            depth += {"(": 1, ")": -1}.get(char, 0)
            if char == "," and depth == 0:
                if text[start:index].strip() == "test":
                    return True
                start = index + 1
    return False


def _block_end(clean: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(clean)):
        if clean[index] == "{":
            depth += 1
        elif clean[index] == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    raise GuardError("unclosed Rust module")


def _normal_path(path: PurePosixPath) -> PurePosixPath:
    parts: list[str] = []
    for part in path.parts:
        if part == "..":
            if not parts:
                raise GuardError("module path escapes source root")
            parts.pop()
        elif part != ".":
            parts.append(part)
    return PurePosixPath(*parts)


def _module_facts(path: PurePosixPath, source: str):
    clean = _blank_literals_and_comments(source)
    modules = list(MODULE.finditer(clean))
    inline = [
        (match.start(), _block_end(clean, match.end() - 1), match.group("name"))
        for match in modules if match.group("end") == "{"
    ]
    test_ranges = [
        (match.start(), _block_end(clean, match.end() - 1))
        for match in modules
        if match.group("end") == "{" and _test_only(match.group("attrs"))
    ]
    in_test = lambda offset: any(start <= offset < end for start, end in test_ranges)
    base = path.parent if path.name in {"lib.rs", "main.rs", "mod.rs"} else path.with_suffix("")
    edges = []
    for match in modules:
        if match.group("end") != ";":
            continue
        attrs = source[match.start("attrs"):match.end("attrs")]
        explicit = PATH_ATTRIBUTE.search(attrs)
        if "path" in match.group("attrs") and explicit is None:
            raise GuardError(f"{path}: unsupported module path attribute")
        parents = [name for start, end, name in inline if start < match.start() < end]
        if explicit:
            target = path.parent.joinpath(*parents, explicit.group(1))
            candidates = [_normal_path(target)]
        else:
            directory = base.joinpath(*parents, match.group("name"))
            candidates = [directory.with_suffix(".rs"), directory / "mod.rs"]
        test_only = _test_only(match.group("attrs")) or in_test(match.start())
        edges.extend((target, test_only) for target in candidates)

    # A second include!/#[path] production reference cancels a test-only exclusion.
    # Computed includes are unsupported rather than silently assumed to be test code.
    for match in re.finditer(r"\binclude\s*!\s*\([^)]*\)", clean):
        raw = source[match.start():match.end()]
        literal = re.fullmatch(r'include\s*!\s*\(\s*"([^"\\]+)"\s*\)', raw)
        if not literal:
            raise GuardError(f"{path}: computed include! needs a reviewed source boundary")
        edges.append((_normal_path(path.parent / literal.group(1)), in_test(match.start())))

    chars = list(clean)
    for start, end in test_ranges:
        chars[start:end] = " " * (end - start)
    return "".join(chars), edges


def production_owners(sources: dict[str, str]) -> set[str]:
    """Only exclude a module when every observed code reference is test-only."""
    cleaned: dict[PurePosixPath, str] = {}
    incoming: dict[PurePosixPath, list[tuple[PurePosixPath, bool]]] = defaultdict(list)
    for name, source in sources.items():
        path = PurePosixPath(name)
        cleaned[path], edges = _module_facts(path, source)
        for target, test_only in edges:
            incoming[target].append((path, test_only))
    excluded: set[PurePosixPath] = set()
    while True:
        newly_excluded = {
            target for target, references in incoming.items()
            if target in cleaned and target not in excluded
            and all(test_only or owner in excluded for owner, test_only in references)
        }
        if not newly_excluded:
            break
        excluded.update(newly_excluded)
    return {
        str(path) for path, source in cleaned.items()
        if path not in excluded and CONSTRUCTOR.search(source)
    }


def repository_sources(root: Path) -> dict[str, str]:
    paths = [
        root / "crates/openbot-infra/src/application_assembly.rs",
        root / "crates/openbot-server/src/main.rs",
        *sorted((root / "crates/openbot-desktop/src").rglob("*.rs")),
    ]
    return {path.relative_to(root).as_posix(): path.read_text(encoding="utf-8") for path in paths}


def main() -> int:
    try:
        root = Path(__file__).resolve().parent.parent
        for owner in sorted(production_owners(repository_sources(root))):
            print(owner)
        return 0
    except (GuardError, OSError) as error:
        print(f"Application assembly source guard: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
