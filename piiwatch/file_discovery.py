"""File discovery for directory scanning.

Kept separate from the CLI module so the same logic can be reused by
future entry points (e.g. a watch-mode daemon, a CI integration) without
depending on click.
"""

from __future__ import annotations

from pathlib import Path

# Extensions we treat as text/log-like by default. Binary files (images,
# archives, etc.) would just produce noise or errors if scanned as text.
DEFAULT_EXTENSIONS = {".log", ".txt", ".json", ".csv", ".out", ".jsonl"}

# Directories that are almost never useful to scan and commonly huge
# (version control internals, virtualenvs, dependency trees).
DEFAULT_EXCLUDED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", ".idea", ".vscode"}


def discover_files(
    root: Path,
    *,
    extensions: set[str] | None = None,
    excluded_dirs: set[str] | None = None,
) -> list[Path]:
    """Recursively find scannable files under `root`.

    If `extensions` is None, every regular file is included (useful when
    a user explicitly wants "everything", e.g. an export directory with
    unusual naming). Pass DEFAULT_EXTENSIONS explicitly to restrict to
    common log/text formats.
    """
    excluded_dirs = excluded_dirs if excluded_dirs is not None else DEFAULT_EXCLUDED_DIRS
    results: list[Path] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in excluded_dirs for part in path.parts):
            continue
        if extensions is not None and path.suffix.lower() not in extensions:
            continue
        results.append(path)

    return results
