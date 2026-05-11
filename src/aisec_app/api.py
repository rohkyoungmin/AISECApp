from __future__ import annotations

from typing import Annotated

try:
    from fastapi import FastAPI, File, Form, HTTPException, UploadFile
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("API dependencies are not installed. Install with `pip install -e .[api,llm]`.") from exc

from .source_analysis import LLMNotConfiguredError, build_source_analyzer
from .zip_analysis import ZipAnalysisLimits, analyze_zip_archive


app = FastAPI(title="AISEC App API", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze/zip")
async def analyze_zip(
    file: Annotated[UploadFile, File(description="ZIP archive containing C/C++ source files.")],
    allow_heuristic: Annotated[bool, Form()] = False,
    max_files: Annotated[int, Form()] = 20,
) -> dict[str, object]:
    content = await file.read()
    try:
        analyzer = build_source_analyzer(require_llm=not allow_heuristic)
        report = analyze_zip_archive(
            archive_name=file.filename or "upload.zip",
            archive_bytes=content,
            analyzer=analyzer,
            limits=ZipAnalysisLimits(max_files=max_files),
        )
    except LLMNotConfiguredError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to analyze ZIP archive: {exc}") from exc
    return report.to_dict()
