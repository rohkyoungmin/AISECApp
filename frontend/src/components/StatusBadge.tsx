interface Props {
  status: string;
  className?: string;
}

const STATUS_MAP: Record<string, { cls: string; label: string }> = {
  pass:         { cls: "badge-pass",   label: "PASS" },
  reject:       { cls: "badge-reject", label: "REJECT" },
  needs_review: { cls: "badge-review", label: "REVIEW" },
};

const SEV_MAP: Record<string, string> = {
  critical: "badge-critical",
  high:     "badge-high",
  medium:   "badge-medium",
  low:      "badge-low",
};

export function StatusBadge({ status, className = "" }: Props) {
  const info = STATUS_MAP[status] ?? { cls: "badge-review", label: status.toUpperCase() };
  return <span className={`badge ${info.cls} ${className}`}>{info.label}</span>;
}

export function SeverityBadge({ status, className = "" }: Props) {
  const cls = SEV_MAP[status.toLowerCase()] ?? "badge-review";
  return <span className={`badge ${cls} ${className}`}>{status.toUpperCase()}</span>;
}
