from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class ReportSummary:
    report_id: str
    archive_name: str
    created_at: str
    verifier_status: str
    analyzed_files: int
    total_findings: int


@dataclass
class Project:
    project_id: str
    name: str
    created_at: str
    reports: list[ReportSummary] = field(default_factory=list)


class ProjectStore:
    _INDEX = "projects.json"

    def __init__(self, store_dir: Path | str = "output") -> None:
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self.store_dir / self._INDEX
        self._projects: dict[str, Project] = {}
        self._load()

    def _load(self) -> None:
        if not self._index_path.exists():
            return
        try:
            data = json.loads(self._index_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        for raw in data.get("projects", []):
            try:
                reports = [ReportSummary(**r) for r in raw.get("reports", [])]
                project = Project(
                    project_id=raw["project_id"],
                    name=raw["name"],
                    created_at=raw["created_at"],
                    reports=reports,
                )
                self._projects[project.project_id] = project
            except (KeyError, TypeError):
                continue

    def _save(self) -> None:
        projects_list = sorted(self._projects.values(), key=lambda p: p.created_at, reverse=True)
        data = {"projects": [asdict(p) for p in projects_list]}
        self._index_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def create_project(self, name: str) -> Project:
        pid = uuid.uuid4().hex[:12]
        project = Project(
            project_id=pid,
            name=name.strip() or "Untitled Project",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._projects[pid] = project
        self._save()
        return project

    def list_projects(self) -> list[Project]:
        return sorted(self._projects.values(), key=lambda p: p.created_at, reverse=True)

    def get_project(self, project_id: str) -> Project | None:
        return self._projects.get(project_id)

    def delete_project(self, project_id: str) -> bool:
        if project_id not in self._projects:
            return False
        del self._projects[project_id]
        self._save()
        return True

    def add_report(self, project_id: str, summary: ReportSummary) -> None:
        project = self._projects.get(project_id)
        if project is None:
            raise KeyError(f"Project '{project_id}' not found")
        project.reports.insert(0, summary)
        self._save()

    def report_dir(self, project_id: str, report_id: str) -> Path:
        path = self.store_dir / project_id / report_id
        path.mkdir(parents=True, exist_ok=True)
        return path
