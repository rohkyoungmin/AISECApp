from __future__ import annotations

import argparse
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class MagmaPatch:
    target: str
    bug_id: str
    path: Path
    text: str


def import_magma_cases(magma_root: str | Path, cases_root: str | Path, overwrite: bool = False) -> list[str]:
    source_root = Path(magma_root)
    output_root = Path(cases_root)
    patch_paths = sorted(source_root.glob("targets/*/patches/bugs/*.patch"))
    imported: list[str] = []

    for patch_path in patch_paths:
        patch = MagmaPatch(
            target=patch_path.parts[-4],
            bug_id=patch_path.stem,
            path=patch_path,
            text=patch_path.read_text(encoding="utf-8", errors="replace").strip(),
        )
        case_id = f"magma-{patch.target}-{patch.bug_id}".lower()
        case_dir = output_root / case_id
        if case_dir.exists() and not overwrite:
            continue

        if case_dir.exists():
            shutil.rmtree(case_dir)
        _write_case(case_dir, patch, case_id)
        imported.append(case_id)

    return imported


def _write_case(case_dir: Path, patch: MagmaPatch, case_id: str) -> None:
    vulnerable_function = _guess_function_name(patch.text)
    vulnerable_address = _guess_source_ref(patch.text, vulnerable_function)
    summary = _summarize_patch(patch)

    manifest = {
        "case_id": case_id,
        "cve_id": f"MAGMA-{patch.bug_id.upper()}",
        "project": patch.target,
        "language": _guess_language(patch.target),
        "source": {
            "benchmark": "Magma",
            "target": patch.target,
            "bug_id": patch.bug_id.upper(),
            "patch_path": str(patch.path),
        },
        "binary": {
            "path": "vulnerable/binary",
            "architecture": "x86_64",
            "compiler": "magma-default",
            "optimization": "unknown",
        },
        "inputs": {
            "advisory": "advisory.txt",
            "patch_diff": "patch.diff",
            "decompiler_excerpt": "vulnerable/decompiler.txt",
        },
        "labels": {
            "expected_verdict": "vulnerable",
            "vulnerable_function": vulnerable_function,
            "vulnerable_address": vulnerable_address,
        },
    }

    (case_dir / "vulnerable").mkdir(parents=True, exist_ok=True)
    (case_dir / "fixed").mkdir(parents=True, exist_ok=True)
    _write_text(case_dir / "manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    _write_text(case_dir / "advisory.txt", summary + "\n")
    _write_text(case_dir / "patch.diff", patch.text + "\n")
    _write_text(case_dir / "vulnerable" / "decompiler.txt", _build_excerpt(patch, vulnerable_function, vulnerable_address))
    _write_text(case_dir / "fixed" / "decompiler.txt", _build_fixed_excerpt(patch, vulnerable_function, vulnerable_address))
    _write_text(case_dir / "vulnerable" / "binary", f"placeholder for {case_id} vulnerable Magma build artifact\n")
    _write_text(case_dir / "fixed" / "binary", f"placeholder for {case_id} fixed Magma build artifact\n")


def _write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _guess_function_name(patch_text: str) -> str:
    for line in patch_text.splitlines():
        if line.startswith("@@"):
            match = re.search(r"@@.*@@\s*(?:[A-Za-z_][\w\s\*]*\s+)?([A-Za-z_]\w*)\s*\(", line)
            if match:
                return match.group(1)
    canary_context = re.search(r"MAGMA_LOG\([^;]+", patch_text)
    if canary_context:
        return "magma_canary_context"
    return "unknown"


def _guess_source_ref(patch_text: str, function_name: str) -> str:
    filename = "source"
    for line in patch_text.splitlines():
        if line.startswith("+++ b/"):
            filename = line.removeprefix("+++ b/")
            break
        if line.startswith("--- a/"):
            filename = line.removeprefix("--- a/")

    line_no = None
    for line in patch_text.splitlines():
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            if match:
                line_no = match.group(1)
                break

    suffix = f":{line_no}" if line_no else ""
    if function_name != "unknown":
        return f"source:{filename}{suffix}:{function_name}"
    return f"source:{filename}{suffix}"


def _summarize_patch(patch: MagmaPatch) -> str:
    touched = ", ".join(_touched_files(patch.text)[:3]) or "source files"
    canaries = _canary_conditions(patch.text)
    if canaries:
        condition = canaries[0]
        return (
            f"Magma {patch.target} bug {patch.bug_id.upper()} is modeled by a patch touching {touched}. "
            f"The Magma canary marks the vulnerable condition `{condition}`."
        )
    return (
        f"Magma {patch.target} bug {patch.bug_id.upper()} is modeled by a patch touching {touched}. "
        "The case should be validated against the patch diff and generated binary evidence."
    )


def _build_excerpt(patch: MagmaPatch, function_name: str, source_ref: str) -> str:
    lines = [
        f"{function_name} @ {source_ref}",
        "Magma-derived source-level excerpt for the vulnerable build.",
        "MAGMA_ENABLE_FIXES is treated as disabled for this placeholder excerpt.",
    ]
    canaries = _canary_conditions(patch.text)
    if canaries:
        lines.append(f"MAGMA_BUG condition: {canaries[0]}")
    lines.append("")
    lines.extend(_interesting_patch_lines(patch.text, include_added=True))
    return "\n".join(lines).strip() + "\n"


def _build_fixed_excerpt(patch: MagmaPatch, function_name: str, source_ref: str) -> str:
    lines = [
        f"{function_name} @ {source_ref}",
        "Magma-derived source-level excerpt for the fixed build.",
        "MAGMA_ENABLE_FIXES is treated as enabled for this placeholder excerpt.",
        "",
    ]
    lines.extend(_interesting_patch_lines(patch.text, include_added=True))
    return "\n".join(lines).strip() + "\n"


def _interesting_patch_lines(patch_text: str, include_added: bool) -> list[str]:
    selected: list[str] = []
    for line in patch_text.splitlines():
        if line.startswith(("diff --git", "index ", "--- ", "+++ ", "@@")):
            selected.append(line)
        elif include_added and line.startswith("+") and not line.startswith("+++"):
            selected.append(line)
        elif line.startswith(" ") and len(selected) < 40:
            selected.append(line)
        if len(selected) >= 80:
            break
    return selected


def _touched_files(patch_text: str) -> list[str]:
    files: list[str] = []
    for line in patch_text.splitlines():
        if line.startswith("+++ b/"):
            files.append(line.removeprefix("+++ b/"))
    return files


def _canary_conditions(patch_text: str) -> list[str]:
    conditions: list[str] = []
    for match in re.finditer(r"MAGMA_LOG\(\"%MAGMA_BUG%\",\s*(.*?)\);", patch_text, flags=re.S):
        condition = " ".join(match.group(1).split())
        conditions.append(condition)
    return conditions


def _guess_language(target: str) -> str:
    if target in {"poppler"}:
        return "C++"
    return "C"


def main() -> None:
    parser = argparse.ArgumentParser(description="Import Magma bug patches into AISEC case directories.")
    parser.add_argument("magma_root", nargs="?", default="external/magma")
    parser.add_argument("cases_root", nargs="?", default="data/cases")
    parser.add_argument("--overwrite", action="store_true", help="Regenerate existing Magma case directories.")
    args = parser.parse_args()

    imported = import_magma_cases(args.magma_root, args.cases_root, overwrite=args.overwrite)
    print(f"Imported {len(imported)} Magma cases")
    for case_id in imported:
        print(case_id)


if __name__ == "__main__":
    main()
