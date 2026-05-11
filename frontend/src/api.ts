import type { Project, ProjectReport } from "./types";

const BASE = "";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, options);
  if (!res.ok) {
    const msg = await res.text().catch(() => res.statusText);
    throw new Error(msg || `HTTP ${res.status}`);
  }
  return res.json();
}

export const api = {
  listProjects: (): Promise<Project[]> => request("/projects"),

  createProject: (name: string): Promise<Project> =>
    request("/projects", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    }),

  getProject: (id: string): Promise<Project> => request(`/projects/${id}`),

  deleteProject: (id: string): Promise<void> =>
    fetch(`${BASE}/projects/${id}`, { method: "DELETE" }).then(() => undefined),

  getReport: (projectId: string, reportId: string): Promise<ProjectReport> =>
    request(`/projects/${projectId}/reports/${reportId}`),

  startAnalysis: async (
    projectId: string,
    file: File,
    options: { allowHeuristic?: boolean; maxFiles?: number } = {}
  ): Promise<{ job_id: string }> => {
    const form = new FormData();
    form.append("file", file);
    form.append("allow_heuristic", String(options.allowHeuristic ?? false));
    form.append("max_files", String(options.maxFiles ?? 20));
    return request(`/projects/${projectId}/analyze`, { method: "POST", body: form });
  },

  pdfUrl: (projectId: string, reportId: string): string =>
    `${BASE}/projects/${projectId}/reports/${reportId}/pdf`,
};
