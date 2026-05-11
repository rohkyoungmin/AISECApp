import { useEffect, useState } from "react";
import { useNavigate, useParams, Link } from "react-router-dom";
import { api } from "../api";
import type { FileReport, ProjectReport, SourceFinding } from "../types";
import Header from "../components/Header";
import { StatusBadge, SeverityBadge } from "../components/StatusBadge";

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = pct >= 80 ? "var(--error)" : pct >= 60 ? "var(--amber)" : "var(--teal)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{
        flex: 1,
        height: 3,
        background: "var(--hairline)",
        borderRadius: 3,
        overflow: "hidden",
        maxWidth: 100,
      }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 3 }} />
      </div>
      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--muted)", minWidth: 36 }}>
        {pct}%
      </span>
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
    <div style={{
      background: "var(--canvas)",
      border: "1px solid var(--hairline)",
      borderRadius: "var(--r-lg)",
      overflow: "hidden",
      opacity: accepted ? 1 : 0.6,
    }}>
      <button
        onClick={() => setOpen((o) => !o)}
        style={{
          width: "100%",
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "12px 16px",
          background: "transparent",
          border: "none",
          cursor: "pointer",
          textAlign: "left",
          color: "var(--ink)",
        }}
      >
        <SeverityBadge status={finding.severity} />
        <span style={{ fontSize: 13, fontWeight: 500, flex: 1, color: "var(--ink)" }}>
          {finding.title}
        </span>
        {!accepted && (
          <span style={{ fontSize: 11, color: "var(--muted-soft)", fontWeight: 500 }}>Rejected</span>
        )}
        {loc && (
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--muted)", flexShrink: 0 }}>
            {loc}
          </span>
        )}
        <span style={{ color: "var(--muted-soft)", fontSize: 10, flexShrink: 0 }}>
          {open ? "▲" : "▼"}
        </span>
      </button>

      {open && (
        <div style={{
          borderTop: "1px solid var(--hairline-soft)",
          padding: "16px 18px",
          background: "var(--surface-soft)",
          display: "flex",
          flexDirection: "column",
          gap: 16,
        }}>
          <div style={{ display: "flex", gap: 20, flexWrap: "wrap", alignItems: "center" }}>
            {finding.function_name && (
              <code style={{
                fontFamily: "var(--font-mono)",
                fontSize: 12,
                color: "var(--primary)",
                background: "rgba(204,120,92,0.08)",
                padding: "2px 8px",
                borderRadius: "var(--r-sm)",
              }}>
                {finding.function_name}()
              </code>
            )}
            <ConfidenceBar value={finding.confidence} />
          </div>

          {finding.root_cause && (
            <div>
              <p style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--muted)", marginBottom: 6 }}>
                Root Cause
              </p>
              <p style={{ fontSize: 13, lineHeight: 1.65, color: "var(--body)" }}>{finding.root_cause}</p>
            </div>
          )}

          {finding.evidence_quote && (
            <div>
              <p style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--muted)", marginBottom: 6 }}>
                Evidence
              </p>
              <pre style={{
                fontFamily: "var(--font-mono)",
                fontSize: 12,
                lineHeight: 1.65,
                padding: "12px 16px",
                background: "var(--surface-dark-soft)",
                color: "var(--on-dark)",
                borderRadius: "var(--r-md)",
                overflow: "auto",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                borderLeft: "3px solid var(--primary)",
              }}>
                {finding.evidence_quote}
              </pre>
            </div>
          )}

          {finding.remediation && (
            <div>
              <p style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--muted)", marginBottom: 6 }}>
                Remediation
              </p>
              <p style={{ fontSize: 13, lineHeight: 1.65, color: "var(--body)" }}>{finding.remediation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FileReportSection({ report }: { report: FileReport }) {
  const [open, setOpen] = useState(report.findings.length > 0);
  const totalFindings = report.findings.length + report.rejected_findings.length;

  return (
    <div style={{
      background: "var(--canvas)",
      border: "1px solid var(--hairline)",
      borderRadius: "var(--r-lg)",
      overflow: "hidden",
      marginBottom: 8,
    }}>
      <button
        onClick={() => setOpen((o) => !o)}
        style={{
          width: "100%",
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "14px 20px",
          background: "transparent",
          border: "none",
          cursor: "pointer",
          textAlign: "left",
        }}
      >
        <span style={{
          fontSize: 9,
          color: "var(--muted-soft)",
          transform: open ? "rotate(90deg)" : "rotate(0deg)",
          transition: "transform 0.15s",
          display: "inline-block",
          flexShrink: 0,
        }}>
          ▶
        </span>
        <span style={{
          fontFamily: "var(--font-mono)",
          fontSize: 13,
          color: "var(--ink)",
          flex: 1,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}>
          {report.filename}
        </span>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexShrink: 0 }}>
          <StatusBadge status={report.verifier_status} />
          <span style={{ fontSize: 12, color: "var(--muted)", fontFamily: "var(--font-mono)" }}>
            {report.findings.length}/{totalFindings}
          </span>
        </div>
      </button>

      {open && (
        <div style={{ borderTop: "1px solid var(--hairline-soft)" }}>
          {report.summary && (
            <div style={{
              padding: "12px 20px",
              fontSize: 13,
              color: "var(--muted)",
              lineHeight: 1.6,
              background: "var(--surface-soft)",
              borderBottom: "1px solid var(--hairline-soft)",
            }}>
              {report.summary}
            </div>
          )}

          {report.findings.length > 0 && (
            <div style={{ padding: "16px 20px" }}>
              <p style={{
                fontSize: 11,
                fontWeight: 600,
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                color: "var(--error)",
                marginBottom: 10,
              }}>
                Accepted Findings
              </p>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {report.findings.map((f, i) => (
                  <FindingCard key={i} finding={f} accepted />
                ))}
              </div>
            </div>
          )}

          {report.rejected_findings.length > 0 && (
            <div style={{
              padding: "16px 20px",
              borderTop: report.findings.length > 0 ? "1px solid var(--hairline-soft)" : "none",
            }}>
              <p style={{
                fontSize: 11,
                fontWeight: 600,
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                color: "var(--muted)",
                marginBottom: 10,
              }}>
                Rejected Findings
              </p>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {report.rejected_findings.map((f, i) => (
                  <FindingCard key={i} finding={f} accepted={false} />
                ))}
              </div>
            </div>
          )}

          {report.findings.length === 0 && report.rejected_findings.length === 0 && (
            <div style={{ padding: "16px 20px", fontSize: 13, color: "var(--muted)" }}>
              No findings.
            </div>
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
      <div className="page-layout">
        <Header />
        <div className="page-content" style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: 300 }}>
          <p style={{ color: "var(--muted)", fontSize: 14 }}>Loading report...</p>
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="page-layout">
        <Header />
        <div className="page-content">
          <p style={{ color: "var(--error)" }}>{error || "Report not found"}</p>
          <button className="btn btn-secondary" style={{ marginTop: 16 }} onClick={() => navigate(`/projects/${projectId}`)}>
            ← Back
          </button>
        </div>
      </div>
    );
  }

  const totalAccepted = report.file_reports.reduce((n, fr) => n + fr.findings.length, 0);
  const totalRejected = report.file_reports.reduce((n, fr) => n + fr.rejected_findings.length, 0);

  const bySeverity: Record<string, number> = {};
  report.file_reports.forEach((fr) => {
    fr.findings.forEach((f) => {
      const s = f.severity.toLowerCase();
      bySeverity[s] = (bySeverity[s] ?? 0) + 1;
    });
  });

  const severityColor: Record<string, string> = {
    critical: "var(--error)",
    high:     "var(--amber)",
    medium:   "var(--warning)",
    low:      "var(--teal)",
  };

  return (
    <div className="page-layout">
      <Header />
      <div className="page-content">
        {/* Back */}
        <Link
          to={`/projects/${projectId}`}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            fontSize: 13,
            color: "var(--muted)",
            fontWeight: 500,
            marginBottom: 24,
          }}
        >
          ← Project
        </Link>

        {/* Report header */}
        <div style={{
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          gap: 16,
          flexWrap: "wrap",
          marginBottom: 40,
          paddingBottom: 32,
          borderBottom: "1px solid var(--hairline)",
        }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
              <StatusBadge status={report.verifier_status} />
              {report.archive_name && (
                <span style={{ fontSize: 13, color: "var(--muted)", fontFamily: "var(--font-mono)" }}>
                  {report.archive_name}
                </span>
              )}
            </div>
            <h1 style={{
              fontFamily: "var(--font-display)",
              fontSize: 36,
              fontWeight: 400,
              letterSpacing: "-0.02em",
              color: "var(--ink)",
              marginBottom: 8,
            }}>
              Security Analysis Report
            </h1>
            <p style={{ fontSize: 13, color: "var(--muted)" }}>
              {report.analyzed_files} of {report.total_files} files analyzed
            </p>
          </div>
          <a
            href={api.pdfUrl(projectId!, reportId!)}
            target="_blank"
            rel="noreferrer"
            className="btn btn-secondary btn-sm"
          >
            ↓ Download PDF
          </a>
        </div>

        {/* Stats */}
        <div style={{ marginBottom: 32, display: "flex", flexDirection: "column", gap: 16 }}>

          {/* Row 1: findings overview */}
          <div>
            <p style={{ fontSize: 11, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "var(--muted-soft)", marginBottom: 8 }}>
              Findings overview
            </p>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
              {[
                { label: "Accepted", sub: "confirmed findings", value: totalAccepted, color: totalAccepted > 0 ? "var(--error)" : "var(--success)" },
                { label: "Rejected", sub: "filtered by verifier", value: totalRejected, color: "var(--muted)" },
                { label: "Files",    sub: "source files scanned", value: report.analyzed_files, color: "var(--ink)" },
              ].map((stat) => (
                <div key={stat.label} style={{ background: "var(--surface-card)", borderRadius: "var(--r-lg)", padding: "16px 20px" }}>
                  <p style={{ fontSize: 11, fontWeight: 500, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--muted)", marginBottom: 4 }}>
                    {stat.label}
                  </p>
                  <p style={{ fontFamily: "var(--font-display)", fontSize: 34, fontWeight: 400, letterSpacing: "-0.02em", color: stat.color, lineHeight: 1, marginBottom: 4 }}>
                    {stat.value}
                  </p>
                  <p style={{ fontSize: 11, color: "var(--muted-soft)" }}>{stat.sub}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Row 2: severity breakdown (only if any accepted findings) */}
          {totalAccepted > 0 && (
            <div>
              <p style={{ fontSize: 11, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "var(--muted-soft)", marginBottom: 8 }}>
                By severity — accepted findings only
              </p>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(110px, 1fr))", gap: 10 }}>
                {["critical", "high", "medium", "low"]
                  .filter((s) => bySeverity[s])
                  .map((s) => (
                    <div key={s} style={{ background: "var(--surface-card)", borderRadius: "var(--r-lg)", padding: "14px 18px", borderTop: `3px solid ${severityColor[s]}` }}>
                      <p style={{ fontFamily: "var(--font-display)", fontSize: 30, fontWeight: 400, letterSpacing: "-0.02em", color: severityColor[s], lineHeight: 1, marginBottom: 4 }}>
                        {bySeverity[s]}
                      </p>
                      <p style={{ fontSize: 11, fontWeight: 500, letterSpacing: "0.05em", textTransform: "uppercase", color: "var(--muted)" }}>
                        {s}
                      </p>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>

        {/* Summary */}
        {report.summary && (
          <div style={{
            background: "var(--surface-card)",
            borderRadius: "var(--r-lg)",
            padding: "20px 24px",
            marginBottom: 36,
            borderLeft: "3px solid var(--primary)",
          }}>
            <p style={{
              fontSize: 11,
              fontWeight: 600,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              color: "var(--muted)",
              marginBottom: 10,
            }}>
              Summary
            </p>
            <p style={{ fontSize: 14, lineHeight: 1.7, color: "var(--body)" }}>{report.summary}</p>
          </div>
        )}

        {/* Files */}
        <div style={{ marginBottom: 24 }}>
          <h3 style={{ fontSize: 15, fontWeight: 500, color: "var(--ink)", marginBottom: 16 }}>
            Files
            <span style={{ color: "var(--muted)", fontWeight: 400, fontSize: 13, marginLeft: 8 }}>
              ({report.file_reports.length})
            </span>
          </h3>
          {report.file_reports.map((fr, i) => (
            <FileReportSection key={i} report={fr} />
          ))}
        </div>

        {/* Skipped */}
        {report.skipped_files.length > 0 && (
          <details style={{ marginTop: 16 }}>
            <summary style={{
              cursor: "pointer",
              fontSize: 13,
              color: "var(--muted)",
              userSelect: "none",
              listStyle: "none",
              display: "flex",
              alignItems: "center",
              gap: 6,
              fontWeight: 500,
            }}>
              ▸ {report.skipped_files.length} skipped {report.skipped_files.length === 1 ? "file" : "files"}
            </summary>
            <div style={{
              marginTop: 12,
              background: "var(--surface-card)",
              borderRadius: "var(--r-lg)",
              padding: "12px 20px",
              display: "flex",
              flexDirection: "column",
              gap: 4,
            }}>
              {report.skipped_files.map((f, i) => (
                <span key={i} style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--muted)" }}>
                  {f}
                </span>
              ))}
            </div>
          </details>
        )}
      </div>
    </div>
  );
}
