from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import BinaryMetadata, CVECase, CaseLabels, CaseRecord, Verdict


class DatasetError(ValueError):
    """Raised when a case directory does not match the dataset contract."""


def load_case(case_dir: str | Path) -> CVECase:
    return load_case_record(case_dir).case


def load_case_record(case_dir: str | Path) -> CaseRecord:
    root = Path(case_dir)
    manifest_path = root / "manifest.json"
    if not manifest_path.exists():
        raise DatasetError(f"missing manifest.json: {manifest_path}")

    manifest = _read_json(manifest_path)
    binary = _require_mapping(manifest, "binary", manifest_path)
    inputs = _require_mapping(manifest, "inputs", manifest_path)
    labels = _require_mapping(manifest, "labels", manifest_path)

    advisory = _read_text(root, _require_str(inputs, "advisory", manifest_path))
    patch_diff = _read_text(root, _require_str(inputs, "patch_diff", manifest_path))
    decompiler_excerpt = _read_text(root, _require_str(inputs, "decompiler_excerpt", manifest_path))

    case = CVECase(
        case_id=_require_str(manifest, "case_id", manifest_path),
        cve_id=_require_str(manifest, "cve_id", manifest_path),
        advisory=advisory,
        binary_metadata=BinaryMetadata(
            path=str(root / _require_str(binary, "path", manifest_path)),
            architecture=_require_str(binary, "architecture", manifest_path),
            compiler=_require_str(binary, "compiler", manifest_path),
            optimization=_require_str(binary, "optimization", manifest_path),
        ),
        patch_diff=patch_diff,
        decompiler_excerpt=decompiler_excerpt,
    )
    return CaseRecord(
        case=case,
        labels=CaseLabels(
            expected_verdict=_parse_verdict(_require_str(labels, "expected_verdict", manifest_path), manifest_path),
            vulnerable_function=_require_str(labels, "vulnerable_function", manifest_path),
            vulnerable_address=_optional_str(labels, "vulnerable_address", manifest_path),
        ),
    )


def load_cases(cases_root: str | Path) -> list[CVECase]:
    return [record.case for record in load_case_records(cases_root)]


def load_case_records(cases_root: str | Path) -> list[CaseRecord]:
    root = Path(cases_root)
    if not root.exists():
        raise DatasetError(f"cases root does not exist: {root}")

    case_dirs = sorted(path for path in root.iterdir() if path.is_dir())
    return [load_case_record(case_dir) for case_dir in case_dirs]


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DatasetError(f"invalid JSON in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise DatasetError(f"manifest must be a JSON object: {path}")
    return data


def _read_text(root: Path, relative_path: str) -> str:
    path = root / relative_path
    if not path.exists():
        raise DatasetError(f"missing case input file: {path}")
    return path.read_text(encoding="utf-8").strip()


def _require_mapping(data: dict[str, Any], key: str, path: Path) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise DatasetError(f"`{key}` must be an object in {path}")
    return value


def _require_str(data: dict[str, Any], key: str, path: Path) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise DatasetError(f"`{key}` must be a non-empty string in {path}")
    return value


def _optional_str(data: dict[str, Any], key: str, path: Path) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise DatasetError(f"`{key}` must be a non-empty string when present in {path}")
    return value


def _parse_verdict(value: str, path: Path) -> Verdict:
    try:
        return Verdict(value)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in Verdict)
        raise DatasetError(f"`expected_verdict` must be one of {allowed} in {path}") from exc
