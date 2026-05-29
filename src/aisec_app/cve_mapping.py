from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .cve_metadata import CVEMetadata, CVEMetadataError, extract_cve_ids, fetch_nvd_keyword_search, parse_nvd_cve_payload
from .models import CVECandidateSummary, SourceArtifact


@dataclass(slots=True)
class CVECandidate:
    cve_id: str
    source: str
    score: float
    match_reasons: list[str] = field(default_factory=list)
    description: str = ""
    weaknesses: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cvss_severity: str = ""
    references: list[str] = field(default_factory=list)
    verified: bool = False
    verifier_rationale: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def to_summary(self) -> CVECandidateSummary:
        return CVECandidateSummary(**self.to_dict())


@dataclass(slots=True)
class NVDMappingAgent:
    cache_dir: Path | None = None
    max_queries: int = 3
    results_per_query: int = 8
    api_key: str | None = None

    def run(self, artifacts: list[SourceArtifact]) -> list[CVEMetadata]:
        queries = build_nvd_queries(artifacts, limit=self.max_queries)
        records: dict[str, CVEMetadata] = {}

        for query in queries:
            for metadata in self._search(query):
                records[metadata.cve_id] = metadata

        return list(records.values())

    def _search(self, query: str) -> list[CVEMetadata]:
        if self.cache_dir is not None:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            cache_path = self.cache_dir / f"{_safe_cache_key(query)}.json"
            if cache_path.exists():
                payload = json.loads(cache_path.read_text(encoding="utf-8"))
                return [_metadata_from_cached(item) for item in payload.get("records", [])]

        try:
            records = fetch_nvd_keyword_search(
                query,
                api_key=self.api_key,
                results_per_page=self.results_per_query,
            )
        except CVEMetadataError:
            records = []

        if self.cache_dir is not None:
            cache_path = self.cache_dir / f"{_safe_cache_key(query)}.json"
            cache_path.write_text(
                json.dumps(
                    {"query": query, "records": [_metadata_to_cached(record) for record in records]},
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        return records


class CVECandidateEvaluationAgent:
    def run(self, artifacts: list[SourceArtifact], metadata_records: list[CVEMetadata]) -> list[CVECandidate]:
        source_text = "\n".join(f"{artifact.filename}\n{artifact.content}" for artifact in artifacts)
        source_terms = _terms(source_text)
        embedded_cves = set(extract_cve_ids(source_text))

        candidates: list[CVECandidate] = []
        for metadata in metadata_records:
            reasons: list[str] = []
            score = 0.0

            if metadata.cve_id in embedded_cves:
                score += 0.65
                reasons.append("source mentions CVE ID")

            description_terms = _terms(metadata.description)
            overlap = sorted(source_terms & description_terms)
            if overlap:
                score += min(0.30, 0.04 * len(overlap))
                reasons.append("NVD description overlap: " + ", ".join(overlap[:6]))

            if _project_name_overlap(artifacts, metadata.description):
                score += 0.20
                reasons.append("project/file name appears in NVD description")

            for weakness in metadata.weaknesses:
                if weakness.lower() in source_text.lower():
                    score += 0.05
                    reasons.append(f"source mentions {weakness}")

            dangerous_overlap = sorted(_dangerous_terms(source_text) & _dangerous_terms(metadata.description))
            if dangerous_overlap:
                score += min(0.15, 0.05 * len(dangerous_overlap))
                reasons.append("vulnerability keyword overlap: " + ", ".join(dangerous_overlap[:4]))

            if score <= 0:
                continue

            cvss_score = metadata.cvss.score if metadata.cvss is not None else None
            cvss_severity = metadata.cvss.severity if metadata.cvss is not None else ""
            candidates.append(
                CVECandidate(
                    cve_id=metadata.cve_id,
                    source=metadata.source,
                    score=round(min(1.0, score), 2),
                    match_reasons=reasons,
                    description=metadata.description,
                    weaknesses=metadata.weaknesses,
                    cvss_score=cvss_score,
                    cvss_severity=cvss_severity,
                    references=metadata.references[:5],
                )
            )

        return sorted(candidates, key=lambda item: (-item.score, item.cve_id))


@dataclass(slots=True)
class CVECandidateVerifierAgent:
    min_score: float = 0.35

    def run(self, candidates: list[CVECandidate]) -> list[CVECandidate]:
        verified: list[CVECandidate] = []
        for candidate in candidates:
            if candidate.score < self.min_score:
                candidate.verified = False
                candidate.verifier_rationale = "candidate score below threshold"
            elif not candidate.description:
                candidate.verified = False
                candidate.verifier_rationale = "NVD description missing"
            elif not candidate.match_reasons:
                candidate.verified = False
                candidate.verifier_rationale = "no source-to-NVD match reason"
            else:
                candidate.verified = True
                candidate.verifier_rationale = "candidate has NVD metadata and source match evidence"
            verified.append(candidate)
        return verified


def map_cve_candidates_from_sources(
    artifacts: list[SourceArtifact],
    *,
    cases_root: str | Path = "data/cases",
    limit: int = 5,
    live_nvd: bool = False,
    cache_dir: str | Path | None = None,
    max_queries: int = 3,
    results_per_query: int = 8,
) -> list[CVECandidate]:
    metadata_records = _local_metadata_records(Path(cases_root))
    if live_nvd:
        agent = NVDMappingAgent(
            cache_dir=Path(cache_dir) if cache_dir is not None else None,
            max_queries=max_queries,
            results_per_query=results_per_query,
            api_key=os.getenv("NVD_API_KEY"),
        )
        metadata_by_id = {record.cve_id: record for record in metadata_records}
        for record in agent.run(artifacts):
            metadata_by_id[record.cve_id] = record
        metadata_records = list(metadata_by_id.values())

    evaluated = CVECandidateEvaluationAgent().run(artifacts, metadata_records)
    verified = CVECandidateVerifierAgent().run(evaluated)
    return verified[:limit]


def build_nvd_queries(artifacts: list[SourceArtifact], limit: int = 3) -> list[str]:
    text = "\n".join(f"{artifact.filename}\n{artifact.content}" for artifact in artifacts)
    lower = text.lower()
    terms = _terms(text)
    dangerous = _dangerous_terms(text)
    queries: list[str] = []

    project_terms = [
        token
        for token in ("openssl", "libpng", "libxml2", "libtiff", "sqlite", "sqlite3", "poppler", "php", "lua", "libsndfile")
        if token in lower
    ]
    if project_terms:
        project = project_terms[0]
        if dangerous:
            queries.append(f"{project} {' '.join(sorted(dangerous)[:2])}")
        queries.append(project)

    cve_ids = extract_cve_ids(text)
    queries.extend(cve_ids[:1])

    function_names = _function_names(text)
    for function_name in function_names[:2]:
        if project_terms:
            queries.append(f"{project_terms[0]} {function_name}")
        else:
            queries.append(function_name)

    if not queries and dangerous:
        queries.append(" ".join(sorted(dangerous)[:3]))
    if not queries and terms:
        queries.append(" ".join(sorted(terms)[:3]))

    deduped: list[str] = []
    for query in queries:
        query = " ".join(query.split())
        if len(query) >= 3 and query not in deduped:
            deduped.append(query)
    return deduped[:limit]


def _local_metadata_records(cases_root: Path) -> list[CVEMetadata]:
    records: list[CVEMetadata] = []
    for manifest_path in sorted(cases_root.glob("*/manifest.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for item in manifest.get("cve_metadata", []):
            if not isinstance(item, dict):
                continue
            payload = {"vulnerabilities": [{"cve": _to_nvd_like_cve(item)}]}
            parsed = parse_nvd_cve_payload(payload)
            if parsed is not None:
                records.append(parsed)
    return records


def _metadata_to_cached(metadata: CVEMetadata) -> dict[str, object]:
    cvss = None
    if metadata.cvss is not None:
        cvss = {
            "version": metadata.cvss.version,
            "score": metadata.cvss.score,
            "severity": metadata.cvss.severity,
            "vector": metadata.cvss.vector,
        }
    return {
        "cve_id": metadata.cve_id,
        "source": metadata.source,
        "status": metadata.status,
        "published": metadata.published,
        "last_modified": metadata.last_modified,
        "description": metadata.description,
        "weaknesses": metadata.weaknesses,
        "cvss": cvss,
        "references": metadata.references,
    }


def _metadata_from_cached(item: dict[str, object]) -> CVEMetadata:
    payload = {"vulnerabilities": [{"cve": _to_nvd_like_cve(item)}]}
    parsed = parse_nvd_cve_payload(payload)
    if parsed is None:
        raise ValueError("invalid cached NVD record")
    return parsed


def _to_nvd_like_cve(item: dict) -> dict:
    cvss = item.get("cvss") if isinstance(item.get("cvss"), dict) else None
    metrics = {}
    if cvss:
        key = "cvssMetricV31" if str(cvss.get("version", "")).startswith("3.1") else "cvssMetricV30"
        metrics[key] = [
            {
                "cvssData": {
                    "version": str(cvss.get("version") or ""),
                    "baseScore": cvss.get("score") or 0.0,
                    "vectorString": str(cvss.get("vector") or ""),
                },
                "baseSeverity": str(cvss.get("severity") or ""),
            }
        ]
    return {
        "id": item.get("cve_id"),
        "vulnStatus": item.get("status"),
        "published": item.get("published"),
        "lastModified": item.get("last_modified"),
        "descriptions": [{"lang": "en", "value": item.get("description", "")}],
        "weaknesses": [{"description": [{"lang": "en", "value": value}]} for value in item.get("weaknesses", [])],
        "metrics": metrics,
        "references": {"referenceData": [{"url": url} for url in item.get("references", [])]},
    }


def _terms(text: str) -> set[str]:
    stopwords = {
        "the", "and", "for", "with", "that", "this", "from", "before", "after",
        "allow", "allows", "remote", "attackers", "cause", "denial", "service",
        "via", "large", "multiple", "function", "source", "return", "void",
        "char", "int", "size", "include", "define", "static", "const",
    }
    return {
        token
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text.lower())
        if token not in stopwords
    }


def _dangerous_terms(text: str) -> set[str]:
    lower = text.lower()
    terms = set()
    patterns = {
        "overflow": ("overflow", "strcpy", "strcat", "sprintf", "memcpy"),
        "memory": ("memory", "malloc", "free", "leak"),
        "ocsp": ("ocsp", "status request", "status_request"),
        "infinite loop": ("infinite loop", "loop"),
        "read": ("read", "recv", "fread"),
    }
    for term, needles in patterns.items():
        if any(needle in lower for needle in needles):
            terms.add(term)
    return terms


def _function_names(text: str) -> list[str]:
    names: list[str] = []
    pattern = re.compile(r"\b([A-Za-z_]\w*)\s*\([^;]*\)\s*\{")
    for match in pattern.finditer(text):
        name = match.group(1)
        if name not in names and name not in {"if", "for", "while", "switch"}:
            names.append(name)
    return names


def _project_name_overlap(artifacts: list[SourceArtifact], description: str) -> bool:
    lower = description.lower()
    for artifact in artifacts:
        for part in Path(artifact.filename).parts:
            token = Path(part).stem.lower()
            if len(token) >= 4 and token in lower:
                return True
    return False


def _safe_cache_key(query: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", query).strip("_")[:80] or "query"
