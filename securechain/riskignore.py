"""Reads and writes the human-editable .riskignore.json exception file.

Exceptions are matched by exact package + version. Upgrading a previously
accepted package to a new (still vulnerable) version is NOT covered by an
old entry - a new exception must be recorded deliberately.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path
from typing import Optional


@dataclass
class RiskException:
    package: str
    version: str
    reason: str
    date: str
    accepted_by: str

    def to_dict(self) -> dict:
        return asdict(self)


def _empty_store() -> dict:
    return {"exceptions": []}


def load_riskignore(ignore_file: str | Path) -> dict:
    path = Path(ignore_file)
    if not path.exists():
        return _empty_store()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Ignore file {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("exceptions"), list):
        raise ValueError(f"Ignore file {path} must be an object with an 'exceptions' array")
    return data


def save_riskignore(ignore_file: str | Path, data: dict) -> None:
    path = Path(ignore_file)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def is_accepted(store: dict, package: str, version: str) -> Optional[RiskException]:
    for entry in store.get("exceptions", []):
        if entry.get("package") == package and entry.get("version") == version:
            return RiskException(**entry)
    return None


def accept_risk(
    ignore_file: str | Path,
    package: str,
    version: str,
    reason: str,
    accepted_by: str,
    accepted_date: Optional[str] = None,
) -> RiskException:
    store = load_riskignore(ignore_file)
    entry_date = accepted_date or date.today().isoformat()

    exceptions = store.setdefault("exceptions", [])
    new_entry = RiskException(
        package=package, version=version, reason=reason, date=entry_date, accepted_by=accepted_by
    )

    for i, existing in enumerate(exceptions):
        if existing.get("package") == package and existing.get("version") == version:
            exceptions[i] = new_entry.to_dict()
            break
    else:
        exceptions.append(new_entry.to_dict())

    save_riskignore(ignore_file, store)
    return new_entry
