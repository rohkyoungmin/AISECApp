import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import type { ProgressEvent } from "../types";

const STAGES = [
  { id: "extracting",   label: "Extract"  },
  { id: "triage",       label: "Triage"   },
  { id: "finding",      label: "Finding"  },
  { id: "verification", label: "Verify"   },
  { id: "reporting",    label: "Report"   },
] as const;

function stageIndex(id: string): number {
  const map: Record<string, number> = {
    start: -1, extracting: 0, triage: 1, finding: 2,
    verification: 2, reporting: 3, finalizing: 3, saving: 4, complete: 5,
  };
  return map[id] ?? -1;
}

type StageStatus = "pending" | "active" | "done";

function getStageStatus(stageIdx: number, currentIdx: number): StageStatus {
  if (currentIdx >= 5) return "done";
  if (stageIdx < currentIdx) return "done";
  if (stageIdx === currentIdx) return "active";
  return "pending";
}

export default function ProgressPage() {
  const { projectId, jobId } = useParams<{ projectId: string; jobId: string }>();
  const navigate = useNavigate();

  const [currentStageId, setCurrentStageId] = useState("start");
  const [currentFile, setCurrentFile] = useState("");
  const [fileIndex, setFileIndex] = useState(0);
  const [totalFiles, setTotalFiles] = useState(0);
  const [messages, setMessages] = useState<string[]>([]);
  const [failed, setFailed] = useState<string | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!jobId) return;
    const es = new EventSource(`/jobs/${jobId}/stream`);

    es.onmessage = (event) => {
      let data: ProgressEvent;
      try { data = JSON.parse(event.data); } catch { return; }

      if (data.type === "heartbeat") return;

      if (data.type === "stage") {
        if (data.stage) setCurrentStageId(data.stage);
        if (data.file) setCurrentFile(data.file);
      }

      if (data.type === "file_start") {
        if (data.file)        setCurrentFile(data.file);
        if (data.file_index)  setFileIndex(data.file_index);
        if (data.total_files) setTotalFiles(data.total_files);
      }

      if (data.message) {
        setMessages((prev) => [...prev.slice(-80), data.message!]);
      } else if (data.file) {
        const label = data.type === "file_start"
          ? `Analyzing ${data.file} (${data.file_index}/${data.total_files})`
          : `${data.stage}: ${data.file}`;
        setMessages((prev) => [...prev.slice(-80), label]);
      }

      if (data.type === "complete") {
        es.close();
        setTimeout(() => {
          navigate(`/projects/${projectId}/reports/${data.report_id}`);
        }, 1200);
      }

      if (data.type === "error") {
        setFailed(data.message ?? "Unknown error");
        es.close();
      }
    };

    es.onerror = () => {
      setFailed("Connection lost. The server may be down.");
      es.close();
    };

    return () => es.close();
  }, [jobId, projectId, navigate]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [messages]);

  const currentIdx = stageIndex(currentStageId);
  const progress = totalFiles > 0 ? fileIndex / totalFiles : 0;
  const isSaving = currentStageId === "saving";

  return (
    <div style={{
      minHeight: "100vh",
      background: "var(--surface-dark)",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      padding: "48px 24px",
    }}>
      {/* Status */}
      <div style={{ textAlign: "center", marginBottom: 52 }}>
        {failed ? (
          <>
            <div style={{ fontSize: 28, marginBottom: 12 }}>⚠</div>
            <h2 style={{
              fontFamily: "var(--font-body)",
              fontWeight: 500,
              fontSize: 20,
              color: "#c64545",
              marginBottom: 8,
            }}>
              Analysis Failed
            </h2>
            <p style={{ color: "var(--on-dark-soft)", fontSize: 14 }}>{failed}</p>
          </>
        ) : isSaving ? (
          <>
            <h2 style={{
              fontFamily: "var(--font-body)",
              fontWeight: 500,
              fontSize: 20,
              color: "var(--on-dark)",
              marginBottom: 8,
            }}>
              Saving report
            </h2>
            <p style={{ color: "var(--on-dark-soft)", fontSize: 13 }}>Redirecting shortly...</p>
          </>
        ) : (
          <>
            <h2 style={{
              fontFamily: "var(--font-body)",
              fontWeight: 500,
              fontSize: 20,
              color: "var(--on-dark)",
              marginBottom: 8,
            }}>
              Analyzing
            </h2>
            <p style={{
              color: "var(--on-dark-soft)",
              fontSize: 12,
              fontFamily: "var(--font-mono)",
              maxWidth: 400,
            }}>
              {currentFile || "Preparing..."}
            </p>
          </>
        )}
      </div>

      {/* Stage steps */}
      <div style={{ display: "flex", alignItems: "center", marginBottom: 40 }}>
        {STAGES.map((stage, i) => {
          const status = getStageStatus(i, currentIdx);
          const prevDone = i > 0 && getStageStatus(i - 1, currentIdx) === "done";
          return (
            <div key={stage.id} style={{ display: "flex", alignItems: "center" }}>
              {i > 0 && (
                <div style={{
                  width: 40,
                  height: 1,
                  background: prevDone || status === "done"
                    ? "var(--success)"
                    : "rgba(255,255,255,0.10)",
                  transition: "background 0.4s",
                }} />
              )}
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
                <div style={{
                  width: 36,
                  height: 36,
                  borderRadius: "50%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 12,
                  fontWeight: 600,
                  border: "2px solid",
                  borderColor: status === "done" ? "var(--success)"
                    : status === "active" ? "var(--primary)"
                    : "rgba(255,255,255,0.12)",
                  background: status === "done" ? "rgba(93,184,114,0.15)"
                    : status === "active" ? "rgba(204,120,92,0.15)"
                    : "transparent",
                  color: status === "done" ? "var(--success)"
                    : status === "active" ? "var(--primary)"
                    : "rgba(255,255,255,0.25)",
                  transition: "all 0.4s",
                }}>
                  {status === "done" ? "✓" : i + 1}
                </div>
                <span style={{
                  fontSize: 10,
                  fontWeight: 500,
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  color: status === "done" ? "var(--success)"
                    : status === "active" ? "var(--primary)"
                    : "rgba(255,255,255,0.22)",
                  transition: "color 0.4s",
                }}>
                  {stage.label}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Progress bar */}
      {totalFiles > 0 && (
        <div style={{ width: 480, maxWidth: "100%", marginBottom: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
            <span style={{ fontSize: 12, color: "var(--on-dark-soft)", fontFamily: "var(--font-mono)" }}>
              {fileIndex} / {totalFiles} files
            </span>
            <span style={{ fontSize: 12, color: "var(--on-dark-soft)", fontFamily: "var(--font-mono)" }}>
              {Math.round(progress * 100)}%
            </span>
          </div>
          <div style={{
            height: 3,
            background: "rgba(255,255,255,0.08)",
            borderRadius: 3,
            overflow: "hidden",
          }}>
            <div style={{
              height: "100%",
              width: `${Math.max(2, progress * 100)}%`,
              background: "var(--primary)",
              borderRadius: 3,
              transition: "width 0.5s ease",
            }} />
          </div>
        </div>
      )}

      {/* Log panel */}
      <div
        ref={logRef}
        style={{
          width: 540,
          maxWidth: "100%",
          height: 220,
          overflowY: "auto",
          background: "var(--surface-dark-soft)",
          border: "1px solid rgba(255,255,255,0.06)",
          borderRadius: "var(--r-lg)",
          padding: "14px 18px",
          fontFamily: "var(--font-mono)",
          fontSize: 12,
          lineHeight: 1.7,
        }}
      >
        {messages.length === 0 && (
          <span style={{ color: "rgba(255,255,255,0.2)" }}>Connecting...</span>
        )}
        {messages.map((msg, i) => (
          <div
            key={i}
            style={{
              color: i === messages.length - 1 ? "var(--on-dark)" : "var(--on-dark-soft)",
              padding: "1px 0",
            }}
          >
            {msg}
          </div>
        ))}
        {failed && (
          <div style={{ color: "#f87171", marginTop: 4 }}>{failed}</div>
        )}
      </div>

      {failed && (
        <button
          className="btn btn-secondary-dark"
          style={{ marginTop: 24 }}
          onClick={() => navigate(`/projects/${projectId}`)}
        >
          ← Back to Project
        </button>
      )}
    </div>
  );
}
