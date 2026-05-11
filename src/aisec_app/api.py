from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

try:
    from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, StreamingResponse
    from fastapi.staticfiles import StaticFiles
except ImportError as exc:
    raise RuntimeError("API dependencies are not installed. Install with `pip install -e .[api,llm]`.") from exc

from .models import ProjectAnalysisReport
from .project_store import ProjectStore, ReportSummary
from .source_analysis import LLMNotConfiguredError, MultiAgentSourceAnalyzer, build_source_analyzer
from .zip_analysis import ZipAnalysisLimits, analyze_zip_archive


_STORE_DIR = Path("output")
_store = ProjectStore(_STORE_DIR)
_jobs: dict[str, dict] = {}  # in-memory job registry

app = FastAPI(title="AISEC App", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ── Projects ──────────────────────────────────────────────────────────────────

@app.get("/projects")
def list_projects():
    return [asdict(p) for p in _store.list_projects()]


@app.post("/projects", status_code=201)
async def create_project(request: Request):
    body = await request.json()
    name = str(body.get("name", "")).strip() or "Untitled Project"
    project = _store.create_project(name)
    return asdict(project)


@app.get("/projects/{project_id}")
def get_project(project_id: str):
    project = _store.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return asdict(project)


@app.delete("/projects/{project_id}", status_code=204)
def delete_project(project_id: str):
    if not _store.delete_project(project_id):
        raise HTTPException(status_code=404, detail="Project not found")


# ── Reports ───────────────────────────────────────────────────────────────────

@app.get("/projects/{project_id}/reports/{report_id}")
def get_report(project_id: str, report_id: str):
    report_path = _STORE_DIR / project_id / report_id / "report.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return json.loads(report_path.read_text(encoding="utf-8"))


@app.get("/projects/{project_id}/reports/{report_id}/pdf")
def download_pdf(project_id: str, report_id: str):
    pdf_path = _STORE_DIR / project_id / report_id / "report.pdf"
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="PDF not found")
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"aisec-report-{report_id}.pdf",
    )


# ── Analysis (SSE) ────────────────────────────────────────────────────────────

@app.post("/projects/{project_id}/analyze")
async def start_analysis(
    project_id: str,
    file: Annotated[UploadFile, File(description="ZIP archive containing C/C++ source files.")],
    allow_heuristic: Annotated[bool, Form()] = False,
    max_files: Annotated[int, Form()] = 20,
):
    project = _store.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    content = await file.read()
    archive_name = file.filename or "upload.zip"
    job_id = uuid.uuid4().hex[:12]
    loop = asyncio.get_event_loop()
    queue: asyncio.Queue = asyncio.Queue()
    _jobs[job_id] = {"status": "running", "queue": queue, "report_id": None}

    def emit(event: dict) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, event)

    def run() -> None:
        try:
            emit({"type": "stage", "stage": "start", "message": "Initializing analysis engine..."})
            analyzer = build_source_analyzer(require_llm=not allow_heuristic)

            if isinstance(analyzer, MultiAgentSourceAnalyzer):
                analyzer.progress = emit

            report = analyze_zip_archive(
                archive_name=archive_name,
                archive_bytes=content,
                analyzer=analyzer,
                limits=ZipAnalysisLimits(max_files=max_files),
                progress_callback=emit,
            )

            emit({"type": "stage", "stage": "saving", "message": "Saving report..."})
            report_id = _save_report(project_id, archive_name, report)
            _jobs[job_id]["report_id"] = report_id
            _jobs[job_id]["status"] = "complete"
            emit({"type": "complete", "report_id": report_id, "project_id": project_id})

        except LLMNotConfiguredError as exc:
            _jobs[job_id]["status"] = "failed"
            emit({"type": "error", "message": str(exc)})
        except Exception as exc:
            _jobs[job_id]["status"] = "failed"
            emit({"type": "error", "message": f"Analysis failed: {exc}"})

    loop.run_in_executor(None, run)
    return {"job_id": job_id}


@app.get("/jobs/{job_id}/stream")
async def stream_job(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    async def generator():
        queue: asyncio.Queue = job["queue"]
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                yield 'data: {"type":"heartbeat"}\n\n'
                continue
            yield f"data: {json.dumps(event)}\n\n"
            if event.get("type") in ("complete", "error"):
                break

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/jobs/{job_id}")
def get_job(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job_id": job_id, "status": job["status"], "report_id": job.get("report_id")}


# ── Static frontend ───────────────────────────────────────────────────────────

_FRONTEND_DIST = Path(__file__).parent.parent.parent / "frontend" / "dist"
if _FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIST), html=True), name="frontend")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _save_report(project_id: str, archive_name: str, report: ProjectAnalysisReport) -> str:
    report_id = uuid.uuid4().hex[:12]
    report_dir = _store.report_dir(project_id, report_id)

    (report_dir / "report.json").write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
    )

    try:
        from .report_export import write_report_pdf
        write_report_pdf(report_dir / "report.pdf", report)
    except Exception:
        pass  # PDF failure is non-fatal

    total_findings = sum(len(fr.findings) for fr in report.file_reports)
    _store.add_report(
        project_id,
        ReportSummary(
            report_id=report_id,
            archive_name=archive_name,
            created_at=datetime.now(timezone.utc).isoformat(),
            verifier_status=report.verifier_status.value,
            analyzed_files=report.analyzed_files,
            total_findings=total_findings,
        ),
    )
    return report_id
