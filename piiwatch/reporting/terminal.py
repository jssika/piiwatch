"""Minimal ANSI terminal formatting helpers.

We deliberately avoid a `rich`/`colorama` dependency here -- a security
scanning tool that people install widely benefits from staying
dependency-light, and the formatting need (colored severity labels +
simple aligned tables) is small enough to hand-roll cleanly.

Color is auto-disabled when stdout isn't a TTY (e.g. piped to a file or
another program) or when the NO_COLOR env var is set, per the
https://no-color.org convention.
"""

from __future__ import annotations

import os
import sys

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_SEVERITY_COLORS = {
    "critical": "\033[1;31m",  # bold red
    "high": "\033[31m",         # red
    "medium": "\033[33m",       # yellow
    "low": "\033[36m",          # cyan
    "info": "\033[37m",         # gray/white
}


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("PIIWATCH_FORCE_COLOR") is not None:
        return True
    return sys.stdout.isatty()


def colorize(text: str, code: str) -> str:
    if not _color_enabled():
        return text
    return f"{code}{text}{_RESET}"


def bold(text: str) -> str:
    return colorize(text, _BOLD)


def dim(text: str) -> str:
    return colorize(text, _DIM)


def severity_label(severity: str) -> str:
    code = _SEVERITY_COLORS.get(severity, "")
    label = severity.upper().ljust(8)
    return colorize(label, code) if code else label


def render_table(rows: list[list[str]], headers: list[str]) -> str:
    """Render a simple aligned table. `rows` and `headers` must have the
    same number of columns. Column widths are computed from visible
    content -- callers should pass already-colorized strings only in the
    severity column, since ANSI codes would otherwise throw off width
    calculation for other columns.
    """
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            visible_len = len(_strip_ansi(cell))
            widths[i] = max(widths[i], visible_len)

    lines = []
    header_line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    lines.append(bold(header_line))
    lines.append(dim("-" * (sum(widths) + 2 * (len(widths) - 1))))

    for row in rows:
        padded_cells = []
        for i, cell in enumerate(row):
            pad = widths[i] - len(_strip_ansi(cell))
            padded_cells.append(cell + " " * max(pad, 0))
        lines.append("  ".join(padded_cells))

    return "\n".join(lines)


def _strip_ansi(text: str) -> str:
    import re

    return re.sub(r"\033\[[0-9;]*m", "", text)
