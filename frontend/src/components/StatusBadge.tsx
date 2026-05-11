interface Props {
  status: string;
  className?: string;
}

const STATUS_MAP: Record<string, { cls: string; label: string }> = {
  pass:         { cls: "badge-pass",   label: "Pass"    },
  reject:       { cls: "badge-reject", label: "Findings" },
  needs_review: { cls: "badge-review", label: "Review"  },
};

const SEV_MAP: Record<string, string> = {
  critical: "badge-critical",
  high:     "badge-high",
  medium:   "badge-medium",
  low:      "badge-low",
};

export function StatusBadge({ status, className = "" }: Props) {
  const info = STATUS_MAP[status] ?? { cls: "badge-review", label: status };
  return <span className={`badge ${info.cls} ${className}`}>{info.label}</span>;
}

export function SeverityBadge({ status, className = "" }: Props) {
  const cls = SEV_MAP[status?.toLowerCase()] ?? "badge-review";
  const label = status
    ? status.charAt(0).toUpperCase() + status.slice(1).toLowerCase()
    : status;
  return <span className={`badge ${cls} ${className}`}>{label}</span>;
}
