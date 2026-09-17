"""Configuration loading.

Detector thresholds live in config/detectors.json, never in the detector code.
That separation is the point: tuning a detection in a real SOC is a config
change reviewed by an analyst, not a code change reviewed by an engineer.

JSON is used rather than YAML so the project has zero runtime dependencies.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "detectors.json"


class Config:
    """Thin wrapper around the parsed config file."""

    def __init__(self, data: dict[str, Any], path: Path | None = None):
        self._data = data
        self.path = path

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        p = Path(path) if path else DEFAULT_CONFIG_PATH
        with open(p, "r", encoding="utf-8") as fh:
            return cls(json.load(fh), p)

    def detector(self, name: str) -> dict[str, Any]:
        """Parameters for one detector. Missing entry == detector disabled."""
        return self._data.get("detectors", {}).get(name, {})

    def enabled_detectors(self) -> list[str]:
        return [
            name
            for name, cfg in self._data.get("detectors", {}).items()
            if cfg.get("enabled", True)
        ]

    @property
    def correlation(self) -> dict[str, Any]:
        return self._data.get("correlation", {})

    @property
    def profiling(self) -> dict[str, Any]:
        return self._data.get("profiling", {})

    @property
    def generator(self) -> dict[str, Any]:
        return self._data.get("generator", {})

    def raw(self) -> dict[str, Any]:
        return self._data
