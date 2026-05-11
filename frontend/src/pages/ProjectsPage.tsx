import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import type { Project } from "../types";
import Header from "../components/Header";
import { StatusBadge } from "../components/StatusBadge";

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function CreateModal({ onClose, onCreate }: { onClose: () => void; onCreate: (p: Project) => void }) {
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
        <h2>New Project</h2>
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
          <button className="btn btn-primary" onClick={submit} disabled={loading || !name.trim()}>
            {loading ? "Creating..." : "Create"}
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
    api.listProjects()
      .then(setProjects)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="page">
      <Header />
      <div className="page-content">
        <div className="page-title-row">
          <h1>Projects</h1>
          <span className="spacer" />
          <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
            + New Project
          </button>
        </div>

        {loading && (
          <p style={{ color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 12 }}>
            Loading...
          </p>
        )}

        {!loading && projects.length === 0 && (
          <div className="empty-state">
            <div className="empty-state-icon">⬡</div>
            <h3 style={{ color: "var(--text-dim)", fontFamily: "var(--head)", fontSize: 14 }}>
              No projects yet
            </h3>
            <p>Create a project and upload a ZIP archive to start analysis.</p>
            <button className="btn btn-outline" style={{ marginTop: 20 }} onClick={() => setShowCreate(true)}>
              + New Project
            </button>
          </div>
        )}

        <div className="grid-2">
          {projects.map((project) => (
            <div
              key={project.project_id}
              className="glow-card project-card"
              onClick={() => navigate(`/projects/${project.project_id}`)}
            >
              <div className="project-card-name">{project.name}</div>
              <div className="project-card-meta">
                <span>{formatDate(project.created_at)}</span>
                <span>{project.reports.length} report{project.reports.length !== 1 ? "s" : ""}</span>
              </div>
              <div className="project-card-reports">
                {project.reports.slice(0, 3).map((r) => (
                  <StatusBadge key={r.report_id} status={r.verifier_status} />
                ))}
                {project.reports.length > 3 && (
                  <span style={{ fontSize: 10, color: "var(--text-dim)", alignSelf: "center" }}>
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
