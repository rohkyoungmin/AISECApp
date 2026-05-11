import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import type { Project } from "../types";
import Header from "../components/Header";
import { StatusBadge } from "../components/StatusBadge";

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, {
    month: "short", day: "numeric", year: "numeric",
  });
}

function CreateModal({
  onClose,
  onCreate,
}: {
  onClose: () => void;
  onCreate: (p: Project) => void;
}) {
  const [name, setName] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit() {
    if (!name.trim()) return;
    setLoading(true);
    try {
      const project = await api.createProject(name.trim());
      onCreate(project);
      onClose();
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">New Project</p>
        <input
          className="input"
          placeholder="Project name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
          autoFocus
        />
        <div className="modal-actions">
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button
            className="btn btn-primary"
            onClick={submit}
            disabled={loading || !name.trim()}
          >
            {loading ? "Creating..." : "Create Project"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    api.listProjects().then(setProjects).finally(() => setLoading(false));
  }, []);

  return (
    <div className="page-layout">
      <Header />
      <div className="page-content">
        {/* Page header */}
        <div style={{
          display: "flex",
          alignItems: "flex-end",
          justifyContent: "space-between",
          marginBottom: 40,
        }}>
          <div>
            <h1 style={{
              fontFamily: "var(--font-display)",
              fontSize: 36,
              fontWeight: 400,
              letterSpacing: "-0.02em",
              color: "var(--ink)",
              marginBottom: 4,
            }}>
              Projects
            </h1>
            {!loading && (
              <p style={{ color: "var(--muted)", fontSize: 14 }}>
                {projects.length} {projects.length === 1 ? "project" : "projects"}
              </p>
            )}
          </div>
          <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
            + New Project
          </button>
        </div>

        {loading && (
          <p style={{ color: "var(--muted)", fontSize: 14 }}>Loading...</p>
        )}

        {!loading && projects.length === 0 && (
          <div style={{
            textAlign: "center",
            padding: "80px 32px",
            background: "var(--surface-card)",
            borderRadius: "var(--r-xl)",
          }}>
            <p style={{ color: "var(--ink)", fontWeight: 500, fontSize: 16, marginBottom: 8 }}>
              No projects yet
            </p>
            <p style={{ color: "var(--muted)", fontSize: 14, marginBottom: 28 }}>
              Create a project to start analyzing C/C++ source code.
            </p>
            <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
              Create your first project
            </button>
          </div>
        )}

        <div className="grid-2">
          {projects.map((project) => (
            <div
              key={project.project_id}
              className="card-canvas card-clickable"
              onClick={() => navigate(`/projects/${project.project_id}`)}
              style={{ padding: "24px" }}
            >
              <h3 style={{
                fontSize: 15,
                fontWeight: 500,
                color: "var(--ink)",
                marginBottom: 6,
              }}>
                {project.name}
              </h3>
              <p style={{ color: "var(--muted)", fontSize: 13, marginBottom: 18 }}>
                {formatDate(project.created_at)} · {project.reports.length}{" "}
                {project.reports.length === 1 ? "report" : "reports"}
              </p>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {project.reports.slice(0, 3).map((r) => (
                  <StatusBadge key={r.report_id} status={r.verifier_status} />
                ))}
                {project.reports.length > 3 && (
                  <span style={{ fontSize: 12, color: "var(--muted-soft)", alignSelf: "center" }}>
                    +{project.reports.length - 3} more
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {showCreate && (
        <CreateModal
          onClose={() => setShowCreate(false)}
          onCreate={(p) => {
            setProjects((prev) => [p, ...prev]);
            navigate(`/projects/${p.project_id}`);
          }}
        />
      )}
    </div>
  );
}
