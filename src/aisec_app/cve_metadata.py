from __future__ import annotations

import argparse
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass(slots=True)
class CVSSMetadata:
    version: str
    score: float
    severity: str
    vector: str


@dataclass(slots=True)
class CVEMetadata:
    cve_id: str
    source: str
    status: str
    published: str
    last_modified: str
    description: str
    weaknesses: list[str] = field(default_factory=list)
    cvss: CVSSMetadata | None = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class EnrichmentResult:
    total_cases: int
    cases_with_cve_candidates: int
    metadata_found: int
    manifests_updated: int
    skipped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class CVEMetadataError(RuntimeError):
    pass


def extract_cve_ids(text: str) -> list[str]:
    return sorted({match.group(0).upper() for match in CVE_PATTERN.finditer(text)})


def discover_case_cve_ids(case_dir: str | Path) -> list[str]:
    root = Path(case_dir)
    chunks: list[str] = []
    manifest_path = root / "manifest.json"
    if manifest_path.exists():
        chunks.append(manifest_path.read_text(encoding="utf-8"))

    for name in ("advisory.txt", "patch.diff"):
        path = root / name
        if path.exists():
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))

    for path in sorted(root.glob("**/decompiler.txt")):
        chunks.append(path.read_text(encoding="utf-8", errors="replace"))

    return extract_cve_ids("\n".join(chunks))


def fetch_nvd_cve(cve_id: str, api_key: str | None = None, timeout: float = 20.0) -> CVEMetadata | None:
    query = urlencode({"cveIds": cve_id.upper()})
    request = Request(f"{NVD_CVE_API_URL}?{query}", headers=_nvd_headers(api_key))
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise CVEMetadataError(f"NVD request failed for {cve_id}: HTTP {exc.code}") from exc
    except (URLError, TimeoutError) as exc:
        raise CVEMetadataError(f"NVD request failed for {cve_id}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CVEMetadataError(f"NVD returned invalid JSON for {cve_id}: {exc}") from exc

    return parse_nvd_cve_payload(payload)


def fetch_nvd_keyword_search(
    keyword_search: str,
    *,
    api_key: str | None = None,
    results_per_page: int = 10,
    timeout: float = 20.0,
) -> list[CVEMetadata]:
    params = {
        "keywordSearch": keyword_search,
        "resultsPerPage": str(max(1, min(results_per_page, 2000))),
        "noRejected": "",
    }
    query = urlencode(params)
    request = Request(f"{NVD_CVE_API_URL}?{query}", headers=_nvd_headers(api_key))
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise CVEMetadataError(f"NVD keyword search failed for {keyword_search!r}: HTTP {exc.code}") from exc
    except (URLError, TimeoutError) as exc:
        raise CVEMetadataError(f"NVD keyword search failed for {keyword_search!r}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CVEMetadataError(f"NVD returned invalid keyword-search JSON for {keyword_search!r}: {exc}") from exc

    return parse_nvd_cve_items(payload)


def parse_nvd_cve_payload(payload: dict[str, Any]) -> CVEMetadata | None:
    items = parse_nvd_cve_items(payload)
    if not items:
        return None
    return items[0]


def parse_nvd_cve_items(payload: dict[str, Any]) -> list[CVEMetadata]:
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return []

    parsed: list[CVEMetadata] = []
    for vulnerability in vulnerabilities:
        cve = vulnerability.get("cve") if isinstance(vulnerability, dict) else None
        if not isinstance(cve, dict):
            continue

        cve_id = _str(cve.get("id"))
        if not cve_id:
            continue

        parsed.append(
            CVEMetadata(
                cve_id=cve_id,
                source="NVD",
                status=_str(cve.get("vulnStatus")) or "unknown",
                published=_str(cve.get("published")),
                last_modified=_str(cve.get("lastModified")),
                description=_english_description(cve.get("descriptions")),
                weaknesses=_weaknesses(cve.get("weaknesses")),
                cvss=_cvss(cve.get("metrics")),
                references=_references(cve.get("references")),
            )
        )

    return parsed


def enrich_cases(
    cases_root: str | Path,
    *,
    write: bool = False,
    api_key: str | None = None,
    delay_seconds: float = 6.0,
    fetcher=fetch_nvd_cve,
) -> EnrichmentResult:
    root = Path(cases_root)
    case_dirs = sorted(path for path in root.iterdir() if path.is_dir())
    skipped: list[str] = []
    cases_with_cve_candidates = 0
    metadata_found = 0
    manifests_updated = 0

    cache: dict[str, CVEMetadata | None] = {}

    for case_dir in case_dirs:
        cve_ids = discover_case_cve_ids(case_dir)
        if not cve_ids:
            skipped.append(f"{case_dir.name}: no CVE ID found")
            continue

        cases_with_cve_candidates += 1
        found: list[CVEMetadata] = []
        for cve_id in cve_ids:
            if cve_id not in cache:
                cache[cve_id] = fetcher(cve_id, api_key=api_key)
                if delay_seconds > 0:
                    time.sleep(delay_seconds)
            metadata = cache[cve_id]
            if metadata is not None:
                found.append(metadata)

        if not found:
            skipped.append(f"{case_dir.name}: CVE IDs found but not returned by NVD ({', '.join(cve_ids)})")
            continue

        metadata_found += len(found)
        if write and _write_manifest_metadata(case_dir / "manifest.json", found):
            manifests_updated += 1

    return EnrichmentResult(
        total_cases=len(case_dirs),
        cases_with_cve_candidates=cases_with_cve_candidates,
        metadata_found=metadata_found,
        manifests_updated=manifests_updated,
        skipped=skipped,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Enrich AISEC case manifests with NVD CVE metadata.")
    parser.add_argument("cases_root", nargs="?", default="data/cases")
    parser.add_argument("--write", action="store_true", help="Write NVD metadata into manifest.json files.")
    parser.add_argument("--delay", type=float, default=6.0, help="Delay between uncached NVD requests.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args()

    result = enrich_cases(
        args.cases_root,
        write=args.write,
        api_key=os.getenv("NVD_API_KEY"),
        delay_seconds=args.delay,
    )
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(_format_result(result))


def _write_manifest_metadata(manifest_path: Path, metadata: list[CVEMetadata]) -> bool:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    existing = manifest.get("cve_metadata")
    next_value = [item.to_dict() for item in metadata]
    if existing == next_value:
        return False

    manifest["cve_metadata"] = next_value
    if _is_internal_cve_id(str(manifest.get("cve_id", ""))) and len(metadata) == 1:
        manifest["linked_cve_id"] = metadata[0].cve_id

    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True


def _format_result(result: EnrichmentResult) -> str:
    lines = [
        f"Cases: {result.total_cases}",
        f"Cases with CVE candidates: {result.cases_with_cve_candidates}",
        f"NVD metadata records found: {result.metadata_found}",
        f"Manifests updated: {result.manifests_updated}",
    ]
    if result.skipped:
        lines.append("Skipped:")
        lines.extend(f"  {item}" for item in result.skipped[:20])
        if len(result.skipped) > 20:
            lines.append(f"  ... {len(result.skipped) - 20} more")
    return "\n".join(lines)


def _nvd_headers(api_key: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "AISECApp/0.1 CVE metadata enrichment",
    }
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _english_description(descriptions: object) -> str:
    if not isinstance(descriptions, list):
        return ""
    fallback = ""
    for item in descriptions:
        if not isinstance(item, dict):
            continue
        value = _str(item.get("value"))
        if not fallback:
            fallback = value
        if _str(item.get("lang")).lower() == "en":
            return value
    return fallback


def _weaknesses(weaknesses: object) -> list[str]:
    values: set[str] = set()
    if not isinstance(weaknesses, list):
        return []
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        for description in weakness.get("description", []):
            if isinstance(description, dict):
                value = _str(description.get("value"))
                if value:
                    values.add(value)
    return sorted(values)


def _cvss(metrics: object) -> CVSSMetadata | None:
    if not isinstance(metrics, dict):
        return None

    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        entry = entries[0]
        if not isinstance(entry, dict):
            continue
        data = entry.get("cvssData")
        if not isinstance(data, dict):
            continue
        score = data.get("baseScore")
        try:
            parsed_score = float(score)
        except (TypeError, ValueError):
            parsed_score = 0.0
        return CVSSMetadata(
            version=_str(data.get("version")) or key.removeprefix("cvssMetric"),
            score=parsed_score,
            severity=_str(entry.get("baseSeverity") or data.get("baseSeverity")),
            vector=_str(data.get("vectorString")),
        )
    return None


def _references(references: object) -> list[str]:
    refs = references.get("referenceData") if isinstance(references, dict) else references
    if not isinstance(refs, list):
        return []
    values = []
    seen = set()
    for item in refs:
        if not isinstance(item, dict):
            continue
        url = _str(item.get("url"))
        if url and url not in seen:
            values.append(url)
            seen.add(url)
    return values[:10]


def _is_internal_cve_id(value: str) -> bool:
    return not bool(CVE_PATTERN.fullmatch(value.strip()))


def _str(value: object) -> str:
    return value if isinstance(value, str) else ""


if __name__ == "__main__":
    main()
