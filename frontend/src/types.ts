export interface ReportSummary {
  report_id: string;
  archive_name: string;
  created_at: string;
  verifier_status: "pass" | "reject" | "needs_review";
  analyzed_files: number;
  total_findings: number;
}

export interface Project {
  project_id: string;
  name: string;
  created_at: string;
  reports: ReportSummary[];
}

export interface SourceFinding {
  title: string;
  verdict: string;
  severity: "critical" | "high" | "medium" | "low" | string;
  function_name: string;
  line_start: number | null;
  line_end: number | null;
  confidence: number;
  root_cause: string;
  evidence_quote: string;
  remediation: string;
}

export interface FileReport {
  report_id: string;
  filename: string;
  verdict: string;
  verifier_status: string;
  verifier_rationale: string;
  model: string;
  summary: string;
  findings: SourceFinding[];
  rejected_findings: SourceFinding[];
}

export interface ProjectReport {
  project_id: string;
  archive_name: string;
  total_files: number;
  analyzed_files: number;
  skipped_files: string[];
  verifier_status: "pass" | "reject" | "needs_review";
  summary: string;
  file_reports: FileReport[];
}

export interface ProgressEvent {
  type: "stage" | "file_start" | "complete" | "error" | "heartbeat";
  stage?: string;
  file?: string;
  file_index?: number;
  total_files?: number;
  message?: string;
  report_id?: string;
  project_id?: string;
}
