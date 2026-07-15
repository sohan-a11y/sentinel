"""Loader for the curated web-relevant CWE catalog.

The dataset is a static, hand-curated JSON file rather than a live API call —
scan runs must not depend on cwe.mitre.org being reachable. Refresh it with
scripts/fetch_cwe_data.py when a new CWE release should be pulled in.
"""
from __future__ import annotations

import json
from pathlib import Path

_DATA_PATH = Path(__file__).resolve().parent / "data" / "cwe_web_relevant.json"


def load_cwe_catalog() -> list[dict]:
    """Returns the curated catalog as a list of {"cwe_id", "name", "category"} dicts."""
    with _DATA_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)
