from __future__ import annotations

import importlib.util
import re
from pathlib import Path

TARGET = Path(__file__).with_name("freeze_osv.py")
spec = importlib.util.spec_from_file_location("freeze_osv", TARGET)
if spec is None or spec.loader is None:
    raise SystemExit("acquisition module unavailable")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

_PATTERNS = tuple(
    re.compile(value, re.IGNORECASE)
    for value in (
        r"\bai\b",
        r"\bml\b",
        r"\bllm\b",
        r"artificial[- ]intelligence",
        r"machine[- ]learning",
        r"large[- ]language[- ]model",
        r"prompt[- ]injection",
        r"generative[- ]model",
        r"chatgpt",
        r"openai",
        r"anthropic",
        r"copilot",
        r"claude",
        r"tensorflow",
        r"pytorch",
        r"transformer",
        r"neural[- ]network",
        r"agentic",
    )
)
_original_parse = module.parse_units


def parse_units(ecosystem: str, archive: Path):
    rows, counts = _original_parse(ecosystem, archive)
    kept = []
    excluded = 0
    for row in rows:
        record = row.get("source_record") or {}
        text = "\n".join(
            (
                str(row.get("package") or ""),
                str(row.get("summary") or ""),
                str(record.get("details") or ""),
            )
        )
        if any(pattern.search(text) for pattern in _PATTERNS):
            excluded += 1
        else:
            kept.append(row)
    counts = dict(counts)
    counts["scope_excluded_before_sampling"] = excluded
    return kept, counts


module.parse_units = parse_units
module.main()
