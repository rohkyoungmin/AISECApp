import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useParams, Link } from "react-router-dom";
import { api } from "../api";
import type { Project } from "../types";
import Header from "../components/Header";
import { StatusBadge } from "../components/StatusBadge";

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, {
    month: "short", day: "numeric", year: "numeric",
  });
}

function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
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
      <div className="page-layout">
        <Header />
        <div className="page-content" style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: 300 }}>
          <p style={{ color: "var(--muted)", fontSize: 14 }}>Loading...</p>
        </div>
      </div>
    );
  }

  if (!project) return null;

  return (
    <div className="page-layout">
      <Header />
      <div className="page-content">
        {/* Back + Title */}
        <div style={{ marginBottom: 40 }}>
          <Link
            to="/projects"
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              fontSize: 13,
              color: "var(--muted)",
              fontWeight: 500,
              marginBottom: 16,
            }}
          >
            ← Projects
          </Link>
          <h1 style={{
            fontFamily: "var(--font-display)",
            fontSize: 36,
            fontWeight: 400,
            letterSpacing: "-0.02em",
            color: "var(--ink)",
          }}>
            {project.name}
          </h1>
        </div>

        <div style={{
          display: "grid",
          gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)",
          gap: 32,
          alignItems: "start",
        }}>
          {/* Upload section */}
          <div>
            <h3 style={{ fontSize: 15, fontWeight: 500, color: "var(--ink)", marginBottom: 16 }}>
              New Analysis
            </h3>

            <div
              className={`upload-zone ${dragOver ? "drag-over" : ""} ${file ? "has-file" : ""}`}
              onClick={() => fileInputRef.current?.click()}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragOver(false);
                const f = e.dataTransfer.files[0];
                if (f) handleFile(f);
              }}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".zip"
                style={{ display: "none" }}
                onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
              />
              {file ? (
                <>
                  <div style={{ fontSize: 28, color: "var(--success)", marginBottom: 8 }}>✓</div>
                  <p style={{ fontWeight: 500, color: "var(--ink)", fontSize: 14 }}>{file.name}</p>
                  <p style={{ fontSize: 12, color: "var(--muted)", marginTop: 4 }}>{formatSize(file.size)}</p>
                </>
              ) : (
                <>
                  <div style={{ fontSize: 28, color: "var(--muted-soft)", marginBottom: 8 }}>↑</div>
                  <p style={{ fontWeight: 500, color: "var(--body)", fontSize: 14 }}>Drop ZIP file here</p>
                  <p style={{ fontSize: 13, color: "var(--muted)", marginTop: 4 }}>or click to browse</p>
                </>
              )}
            </div>

            {error && (
              <p style={{ color: "var(--error)", fontSize: 13, marginTop: 8 }}>{error}</p>
            )}

            {/* Options */}
            <div style={{
              background: "var(--surface-card)",
              borderRadius: "var(--r-lg)",
              padding: "16px 20px",
              marginTop: 16,
              display: "flex",
              flexDirection: "column",
              gap: 12,
            }}>
              <label style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                cursor: "pointer",
                fontSize: 13,
                color: "var(--body)",
              }}>
                <input
                  type="checkbox"
                  checked={allowHeuristic}
                  onChange={(e) => setAllowHeuristic(e.target.checked)}
                  style={{ accentColor: "var(--primary)", width: 14, height: 14 }}
                />
                Use heuristic mode (no API key needed)
              </label>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ fontSize: 13, color: "var(--muted)", whiteSpace: "nowrap" }}>Max files</span>
                <input
                  type="number"
                  min={1}
                  max={200}
                  value={maxFiles}
                  onChange={(e) => setMaxFiles(Number(e.target.value))}
                  className="input"
                  style={{ width: 80, height: 34, fontSize: 13 }}
                />
              </div>
            </div>

            <button
              className="btn btn-primary"
              disabled={!file || uploading}
              onClick={startAnalysis}
              style={{ marginTop: 16, width: "100%", justifyContent: "center" }}
            >
              {uploading ? "Starting..." : "Start Analysis"}
            </button>
          </div>

          {/* History */}
          <div>
            <h3 style={{ fontSize: 15, fontWeight: 500, color: "var(--ink)", marginBottom: 16 }}>
              Analysis History
              {project.reports.length > 0 && (
                <span style={{ color: "var(--muted)", fontWeight: 400, fontSize: 13, marginLeft: 8 }}>
                  ({project.reports.length})
                </span>
              )}
            </h3>

            {project.reports.length === 0 ? (
              <div style={{
                textAlign: "center",
                padding: "40px 24px",
                background: "var(--surface-card)",
                borderRadius: "var(--r-lg)",
              }}>
                <p style={{ color: "var(--muted)", fontSize: 13 }}>
                  No analyses yet. Upload a ZIP to start.
                </p>
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {[...project.reports].reverse().map((r) => (
                  <Link
                    key={r.report_id}
                    to={`/projects/${projectId}/reports/${r.report_id}`}
                    style={{ textDecoration: "none" }}
                  >
                    <div className="card-canvas card-clickable" style={{ padding: "16px 20px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                        <StatusBadge status={r.verifier_status} />
                        <span style={{ fontSize: 12, color: "var(--muted)", marginLeft: "auto" }}>
                          {formatDate(r.created_at)}
                        </span>
                      </div>
                      <p style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: 12,
                        color: "var(--body)",
                        marginBottom: 6,
                      }}>
                        {r.archive_name}
                      </p>
                      <div style={{ display: "flex", gap: 16, fontSize: 12, color: "var(--muted)" }}>
                        <span>{r.analyzed_files} files</span>
                        <span style={{ color: r.total_findings > 0 ? "var(--error)" : "var(--muted)" }}>
                          {r.total_findings} findings
                        </span>
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
