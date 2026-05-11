import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import type { ProgressEvent } from "../types";

const STAGES = [
  { id: "extracting", icon: "📦", label: "EXTRACT" },
  { id: "triage",     icon: "🔍", label: "TRIAGE"  },
  { id: "finding",    icon: "⚡",  label: "FINDING" },
  { id: "verification", icon: "🛡", label: "VERIFY" },
  { id: "reporting",  icon: "📊", label: "REPORT"  },
] as const;

type StageId = typeof STAGES[number]["id"];

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

  const [currentStageId, setCurrentStageId] = useState<string>("start");
  const [currentFile, setCurrentFile] = useState<string>("");
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

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [messages]);

  const currentIdx = stageIndex(currentStageId);
  const progress = totalFiles > 0 ? fileIndex / totalFiles : 0;

  return (
    <div className="progress-page">
      <p className="progress-title">
        {failed ? "⚠ ANALYSIS FAILED" : currentStageId === "saving" ? "✓ SAVING REPORT..." : "ANALYZING..."}
      </p>

      {/* Pipeline visualization */}
      <div className="pipeline">
        {STAGES.map((stage, i) => {
          const status = getStageStatus(i, currentIdx) as StageStatus;
          return (
            <div key={stage.id} style={{ display: "flex", alignItems: "center" }}>
              <div className="pipeline-stage">
                <div className={`pipeline-stage-box ${status}`}>
                  <span className="pipeline-stage-icon">{stage.icon}</span>
                  <span className="pipeline-stage-label">{stage.label}</span>
                </div>
              </div>
              {i < STAGES.length - 1 && (
                <div className={`pipeline-connector ${status === "done" ? "active" : ""}`} />
              )}
            </div>
          );
        })}
      </div>

      {/* File progress */}
      <div className="progress-file-info">
        {currentFile ? (
          <>
            {totalFiles > 0 && <span>[{fileIndex}/{totalFiles}]&nbsp;</span>}
            <span>{currentFile}</span>
          </>
        ) : (
          <span>&nbsp;</span>
        )}
      </div>

      <div className="progress-bar-wrap">
        <div
          className="progress-bar-fill"
          style={{ width: `${Math.max(2, progress * 100)}%` }}
        />
      </div>

      {/* Log panel */}
      <div className="log-panel" ref={logRef}>
        {messages.length === 0 && (
          <div className="log-line">Connecting to analysis engine...</div>
        )}
        {messages.map((msg, i) => (
          <div key={i} className="log-line">{msg}</div>
        ))}
        {failed && (
          <div className="log-line" style={{ color: "var(--red)" }}>
            {failed}
          </div>
        )}
      </div>

      {failed && (
        <button
          className="btn btn-outline"
          style={{ marginTop: 24 }}
          onClick={() => navigate(`/projects/${projectId}`)}
        >
          ← Back to Project
        </button>
      )}
    </div>
  );
}
