from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class AtomicTechnique:
    category: str
    technique_id: str
    description: str


def load_atomic_catalog(path: str | Path) -> list[dict[str, Any]]:
    """Load a documented Atomic-style metadata manifest; does not execute EVTX tests."""
    manifest_path = Path(path)
    try:
        catalog = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read atomic catalog {manifest_path}: {exc}") from exc
    if (
        not isinstance(catalog, dict)
        or isinstance(catalog.get("schema_version"), bool)
        or catalog.get("schema_version") != 1
        or not isinstance(catalog.get("cases"), list)
    ):
        raise ValueError("Atomic catalog must contain schema_version 1 and a cases list")
    for index, case in enumerate(catalog["cases"]):
        if (
            not isinstance(case, dict)
            or not isinstance(case.get("case_id"), str)
            or not isinstance(case.get("status"), str)
        ):
            raise ValueError(f"Invalid atomic catalog case at index {index}")
        if case["status"] != "fixture":
            raise ValueError(f"Unsupported atomic catalog status at index {index}")
    return catalog["cases"]


def load_atomic_techniques(path: str | Path) -> tuple[AtomicTechnique, ...]:
    """Read operator-supplied Atomic metadata locally; never execute its tests."""
    catalog_path = Path(path)
    try:
        if catalog_path.stat().st_size > 64_000_000:
            raise ValueError("Atomic metadata CSV exceeds the 64 MB limit")
        with catalog_path.open("r", encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            required = {"Category", "TTP ID", "Description"}
            if reader.fieldnames is None or not required.issubset(reader.fieldnames):
                raise ValueError(
                    "Atomic metadata CSV must contain Category, TTP ID, and Description columns"
                )
            techniques = []
            for line_number, row in enumerate(reader, start=2):
                category = (row.get("Category") or "").strip()
                technique_id = (row.get("TTP ID") or "").strip()
                description = " ".join((row.get("Description") or "").split())
                if not category or not technique_id or not description:
                    raise ValueError(
                        f"Atomic metadata CSV has an incomplete row at line {line_number}"
                    )
                techniques.append(
                    AtomicTechnique(category, technique_id, description)
                )
    except OSError as exc:
        raise ValueError(f"Unable to read Atomic metadata CSV {catalog_path}: {exc}") from exc
    return tuple(techniques)


def summarize_atomic_techniques(
    techniques: tuple[AtomicTechnique, ...],
) -> dict[str, int]:
    return dict(Counter(technique.category for technique in techniques))
