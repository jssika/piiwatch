"""Minimal stand-in test runner for environments without pytest installed.

Discovers test_*.py modules in tests/, imports them, and calls every
top-level function whose name starts with `test_`. Once pytest is
available (e.g. via `pip install -e ".[dev]"`), just run `pytest` instead
-- this script is a stopgap, not a replacement.
"""

from __future__ import annotations

import importlib
import inspect
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

TESTS_DIR = Path(__file__).parent / "tests"


def discover_test_modules() -> list[str]:
    return [
        f"tests.{p.stem}"
        for p in sorted(TESTS_DIR.glob("test_*.py"))
    ]


def main() -> int:
    sys.path.insert(0, str(Path(__file__).parent))
    total = 0
    failed = 0
    failures = []

    for module_name in discover_test_modules():
        module = importlib.import_module(module_name)
        test_funcs = [
            getattr(module, name)
            for name in dir(module)
            if name.startswith("test_") and callable(getattr(module, name))
        ]
        for func in test_funcs:
            total += 1
            try:
                sig = inspect.signature(func)
                if "tmp_path" in sig.parameters:
                    tmp_dir = tempfile.mkdtemp(prefix="piiwatch_test_")
                    try:
                        func(tmp_path=Path(tmp_dir))
                    finally:
                        shutil.rmtree(tmp_dir, ignore_errors=True)
                else:
                    func()
                print(f"PASS  {module_name}.{func.__name__}")
            except Exception:
                failed += 1
                print(f"FAIL  {module_name}.{func.__name__}")
                failures.append((f"{module_name}.{func.__name__}", traceback.format_exc()))

    print(f"\n{total - failed}/{total} passed")
    if failures:
        print("\n--- FAILURES ---")
        for name, tb in failures:
            print(f"\n{name}\n{tb}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
