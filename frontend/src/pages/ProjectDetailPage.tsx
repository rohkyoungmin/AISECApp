import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useParams, Link } from "react-router-dom";
import { api } from "../api";
import type { Project } from "../types";
import Header from "../components/Header";
import { StatusBadge } from "../components/StatusBadge";

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

export default function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();

  const [project, setProject] = useState<Project | null>(null);
  const [loading, setLoading] = useState(true);
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [allowHeuristic, setAllowHeuristic] = useState(false);
  const [maxFiles, setMaxFiles] = useState(20);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!projectId) return;
    api.getProject(projectId)
      .then(setProject)
      .catch(() => navigate("/projects"))
      .finally(() => setLoading(false));
  }, [projectId, navigate]);

  const handleFile = useCallback((f: File) => {
    if (f.name.endsWith(".zip")) { setFile(f); setError(null); }
    else setError("Only .zip files are supported.");
  }, []);

  async function startAnalysis() {
    if (!file || !projectId) return;
    setUploading(true);
    setError(null);
    try {
      const { job_id } = await api.startAnalysis(projectId, file, { allowHeuristic, maxFiles });
      navigate(`/projects/${projectId}/jobs/${job_id}`);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Upload failed");
      setUploading(false);
    }
  }

  if (loading) {
    return (
      <div className="page">
        <Header />
        <div className="page-content" style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: 300 }}>
          <p style={{ color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 12 }}>Loading...</p>
        </div>
      </div>
    );
  }

  if (!project) return null;

  return (
    <div className="page">
      <Header />
      <div className="page-content">
        <div className="page-title-row">
          <Link to="/projects" className="btn btn-ghost" style={{ padding: "6px 10px" }}>← Back</Link>
          <h1>{project.name}</h1>
        </div>

        {/* Upload zone */}
        <div className="glow-card" style={{ marginBottom: 32 }}>
          <h2 style={{ fontSize: 14, marginBottom: 20, color: "var(--blue)" }}>New Analysis</h2>

          <div
            className={`upload-zone ${dragOver ? "drag-over" : ""}`}
            onClick={() => fileInputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
          >
            <div className="upload-icon">⬆</div>
            <p className="upload-label">Drop ZIP archive here or click to browse</p>
            <p className="upload-hint">C/C++ source files only · max {maxFiles} files analyzed</p>
            <input
              ref={fileInputRef}
              type="file"
              accept=".zip"
              style={{ display: "none" }}
              onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
            />
          </div>

          {file && (
            <div className="upload-file-selected">
              <span>📦</span>
              <span>{file.name}</span>
              <span style={{ color: "var(--text-dim)", marginLeft: "auto" }}>
                {(file.size / 1024).toFixed(1)} KB
              </span>
              <button
                className="btn btn-ghost"
                style={{ padding: "2px 8px", fontSize: 11 }}
                onClick={() => setFile(null)}
              >
                ✕
              </button>
            </div>
          )}

          {error && (
            <p style={{ color: "var(--red)", fontFamily: "var(--mono)", fontSize: 11, marginTop: 8 }}>
              {error}
            </p>
          )}

          {/* Options */}
          <div style={{ display: "flex", gap: 24, marginTop: 16, flexWrap: "wrap" }}>
            <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={allowHeuristic}
                onChange={(e) => setAllowHeuristic(e.target.checked)}
                style={{ accentColor: "var(--blue)" }}
              />
              <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)" }}>
                Use heuristic (no API key)
              </span>
            </label>

            <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)" }}>
                Max files:
              </span>
              <input
                type="number"
                min={1}
                max={50}
                value={maxFiles}
                onChange={(e) => setMaxFiles(Number(e.target.value))}
                className="input"
                style={{ width: 70 }}
              />
            </label>
          </div>

          <div style={{ marginTop: 20 }}>
            <button
              className="btn btn-primary"
              disabled={!file || uploading}
              onClick={startAnalysis}
            >
              {uploading ? "Starting..." : "Start Analysis"}
            </button>
          </div>
        </div>

        {/* Past reports */}
        {project.reports.length > 0 && (
          <>
            <h2 style={{ fontSize: 14, color: "var(--blue)", marginBottom: 16 }}>
              Analysis History
            </h2>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {project.reports.map((r) => (
                <Link
                  key={r.report_id}
                  to={`/projects/${projectId}/reports/${r.report_id}`}
                  style={{ textDecoration: "none" }}
                >
                  <div className="glow-card" style={{ padding: "14px 18px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                      <StatusBadge status={r.verifier_status} />
                      <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)" }}>
                        {r.archive_name}
                      </span>
                      <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)", marginLeft: "auto" }}>
                        {formatDate(r.created_at)}
                      </span>
                    </div>
                    <div style={{ display: "flex", gap: 20, marginTop: 8, fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)" }}>
                      <span>{r.analyzed_files} files</span>
                      <span style={{ color: r.total_findings > 0 ? "var(--red)" : "var(--text-dim)" }}>
                        {r.total_findings} finding{r.total_findings !== 1 ? "s" : ""}
                      </span>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
