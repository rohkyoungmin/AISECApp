import { useEffect, useState } from "react";
import { useNavigate, useParams, Link } from "react-router-dom";
import { api } from "../api";
import type { FileReport, ProjectReport, SourceFinding } from "../types";
import Header from "../components/Header";
import { StatusBadge, SeverityBadge } from "../components/StatusBadge";

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = pct >= 80 ? "var(--red)" : pct >= 60 ? "var(--orange)" : "var(--blue)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ flex: 1, height: 4, background: "var(--bg3)", borderRadius: 2, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 2 }} />
      </div>
      <span style={{ fontFamily: "var(--mono)", fontSize: 11, color, minWidth: 36 }}>{pct}%</span>
    </div>
  );
}

function FindingCard({ finding, accepted }: { finding: SourceFinding; accepted: boolean }) {
  const [open, setOpen] = useState(accepted);
  const loc = finding.line_start != null
    ? finding.line_end != null && finding.line_end !== finding.line_start
      ? `L${finding.line_start}–${finding.line_end}`
      : `L${finding.line_start}`
    : null;

  return (
    <div className={`finding-card ${accepted ? "" : "rejected"}`}>
      <div className="finding-card-header" onClick={() => setOpen((o) => !o)}>
        <SeverityBadge status={finding.severity} />
        <span className="finding-card-title">{finding.title}</span>
        {!accepted && (
          <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)" }}>REJECTED</span>
        )}
        {loc && (
          <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)" }}>{loc}</span>
        )}
        <span style={{ color: "var(--text-dim)", fontSize: 12 }}>{open ? "▲" : "▼"}</span>
      </div>

      {open && (
        <div className="finding-card-body">
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
            <div className="finding-field" style={{ minWidth: 160 }}>
              <label>Function</label>
              <p style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{finding.function_name}</p>
            </div>
            <div className="finding-field" style={{ flex: 1 }}>
              <label>Confidence</label>
              <ConfidenceBar value={finding.confidence} />
            </div>
          </div>

          <div className="finding-field">
            <label>Root Cause</label>
            <p>{finding.root_cause}</p>
          </div>

          <div className="finding-field">
            <label>Evidence</label>
            <div className="evidence-quote">{finding.evidence_quote}</div>
          </div>

          <div className="finding-field">
            <label>Remediation</label>
            <p>{finding.remediation}</p>
          </div>
        </div>
      )}
    </div>
  );
}

function FileReportSection({ report }: { report: FileReport }) {
  const [open, setOpen] = useState(report.findings.length > 0);
  const totalFindings = report.findings.length + report.rejected_findings.length;

  return (
    <div style={{ marginBottom: 4 }}>
      <div className="file-report-header" onClick={() => setOpen((o) => !o)}>
        <StatusBadge status={report.verifier_status} />
        <span className="file-report-name">{report.filename}</span>
        <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)" }}>
          {report.findings.length}/{totalFindings} accepted
        </span>
        <span className="file-report-toggle">{open ? "▲" : "▼"}</span>
      </div>

      {open && (
        <div style={{ paddingLeft: 8 }}>
          <p style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 12, paddingTop: 4 }}>
            {report.summary}
          </p>

          {report.findings.length > 0 && (
            <>
              <p style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--green)", marginBottom: 6, letterSpacing: "0.1em" }}>
                ✓ ACCEPTED FINDINGS
              </p>
              {report.findings.map((f, i) => (
                <FindingCard key={i} finding={f} accepted />
              ))}
            </>
          )}

          {report.rejected_findings.length > 0 && (
            <>
              <p style={{
                fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)",
                marginBottom: 6, marginTop: 12, letterSpacing: "0.1em",
              }}>
                ✗ REJECTED FINDINGS
              </p>
              {report.rejected_findings.map((f, i) => (
                <FindingCard key={i} finding={f} accepted={false} />
              ))}
            </>
          )}

          {report.findings.length === 0 && report.rejected_findings.length === 0 && (
            <p style={{ fontSize: 12, color: "var(--text-dim)", padding: "8px 0" }}>No findings.</p>
          )}
        </div>
      )}
    </div>
  );
}

export default function ReportPage() {
  const { projectId, reportId } = useParams<{ projectId: string; reportId: string }>();
  const navigate = useNavigate();

  const [report, setReport] = useState<ProjectReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!projectId || !reportId) return;
    api.getReport(projectId, reportId)
      .then(setReport)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [projectId, reportId]);

  if (loading) {
    return (
      <div className="page">
        <Header />
        <div className="page-content" style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: 300 }}>
          <p style={{ color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 12 }}>Loading report...</p>
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="page">
        <Header />
        <div className="page-content">
          <p style={{ color: "var(--red)", fontFamily: "var(--mono)" }}>{error || "Report not found"}</p>
          <button className="btn btn-outline" style={{ marginTop: 16 }} onClick={() => navigate(`/projects/${projectId}`)}>
            ← Back
          </button>
        </div>
      </div>
    );
  }

  const totalAccepted = report.file_reports.reduce((n, fr) => n + fr.findings.length, 0);
  const totalRejected = report.file_reports.reduce((n, fr) => n + fr.rejected_findings.length, 0);

  // Group findings by severity for summary
  const bySeverity: Record<string, number> = {};
  report.file_reports.forEach((fr) => {
    fr.findings.forEach((f) => {
      const s = f.severity.toLowerCase();
      bySeverity[s] = (bySeverity[s] ?? 0) + 1;
    });
  });

  return (
    <div className="page">
      <Header />
      <div className="page-content">
        {/* Header */}
        <div className="report-header">
          <div style={{ display: "flex", alignItems: "flex-start", gap: 16, flexWrap: "wrap" }}>
            <div style={{ flex: 1 }}>
              <h1>Security Analysis Report</h1>
              <div className="report-meta" style={{ marginTop: 8 }}>
                <StatusBadge status={report.verifier_status} />
                <span className="report-meta-item">
                  <strong>{report.archive_name}</strong>
                </span>
                <span className="report-meta-item">
                  {report.analyzed_files} / {report.total_files} files
                </span>
                <span className="report-meta-item" style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)" }}>
                  {report.project_id}
                </span>
              </div>
            </div>
            <div className="report-actions">
              <Link to={`/projects/${projectId}`} className="btn btn-ghost" style={{ padding: "8px 14px" }}>
                ← Project
              </Link>
              <a
                href={api.pdfUrl(projectId!, reportId!)}
                target="_blank"
                rel="noreferrer"
                className="btn btn-outline"
              >
                ↓ PDF
              </a>
            </div>
          </div>
        </div>

        {/* Stats */}
        <div className="report-stats-row">
          <div className="report-stat-box">
            <span className="report-stat-val">{report.analyzed_files}</span>
            <span className="report-stat-lbl">Files</span>
          </div>
          <div className="report-stat-box">
            <span className="report-stat-val" style={{ color: totalAccepted > 0 ? "var(--red)" : "var(--green)" }}>
              {totalAccepted}
            </span>
            <span className="report-stat-lbl">Accepted</span>
          </div>
          <div className="report-stat-box">
            <span className="report-stat-val" style={{ color: "var(--text-dim)" }}>{totalRejected}</span>
            <span className="report-stat-lbl">Rejected</span>
          </div>
          {["critical", "high", "medium", "low"].map((sev) =>
            bySeverity[sev] ? (
              <div key={sev} className="report-stat-box">
                <span className="report-stat-val" style={{
                  color: sev === "critical" ? "#ff4466" : sev === "high" ? "var(--orange)" :
                         sev === "medium" ? "var(--yellow)" : "var(--blue)",
                }}>
                  {bySeverity[sev]}
                </span>
                <span className="report-stat-lbl">{sev.toUpperCase()}</span>
              </div>
            ) : null
          )}
        </div>

        {/* Summary */}
        <div className="report-summary-box">{report.summary}</div>

        {/* File reports */}
        <div>
          {report.file_reports.map((fr, i) => (
            <FileReportSection key={i} report={fr} />
          ))}
        </div>

        {report.skipped_files.length > 0 && (
          <details style={{ marginTop: 24 }}>
            <summary style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)", cursor: "pointer" }}>
              {report.skipped_files.length} skipped file(s)
            </summary>
            <div style={{ paddingLeft: 16, paddingTop: 8 }}>
              {report.skipped_files.map((f, i) => (
                <p key={i} style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)", padding: "2px 0" }}>{f}</p>
              ))}
            </div>
          </details>
        )}
      </div>
    </div>
  );
}
