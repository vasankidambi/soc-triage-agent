from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def sample_alert() -> dict[str, Any]:
    with (PROJECT_ROOT / "sample_data" / "suspicious_login_alert.json").open(
        encoding="utf-8"
    ) as handle:
        return json.load(handle)
