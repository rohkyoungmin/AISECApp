import { useNavigate } from "react-router-dom";

/* ── Static data ─────────────────────────────────────────────────────────── */

const STAGES = [
  { label: "Extract ", msg: "12 files found"        },
  { label: "Triage  ", msg: "12 files queued"       },
  { label: "Finding ", msg: "scanning with Claude"  },
  { label: "Verify  ", msg: "3 findings confirmed"  },
  { label: "Report  ", msg: "PDF saved"             },
];

const FINDINGS = [
  {
    severity: "CRITICAL",
    title: "buffer overflow in ASN1_item_ex_d2i",
    file: "ssl/asn1.c", line: "L112", conf: "94%",
    color: "#f87171", bg: "rgba(248,113,113,0.12)",
  },
  {
    severity: "HIGH",
    title: "use-after-free in SSL_clear",
    file: "ssl/ssl_lib.c", line: "L287", conf: "82%",
    color: "#fb923c", bg: "rgba(251,146,60,0.12)",
  },
  {
    severity: "MEDIUM",
    title: "integer overflow in dtls1_read_bytes",
    file: "ssl/d1_pkt.c", line: "L451", conf: "71%",
    color: "#fbbf24", bg: "rgba(251,191,36,0.10)",
  },
];

const PIPELINE = [
  {
    num: "01",
    name: "Extract",
    desc: "Upload a ZIP archive. Reporter unpacks it, filters C/C++ source files, and queues them for analysis.",
  },
  {
    num: "02",
    name: "Triage",
    desc: "The Triage Agent scans each file for high-risk patterns and prioritizes the analysis order.",
  },
  {
    num: "03",
    name: "Finding",
    desc: "Claude examines each file in depth — identifying vulnerabilities, root causes, and verbatim evidence quotes.",
  },
  {
    num: "04",
    name: "Verify + Report",
    desc: "A skeptic agent confirms every finding has real evidence in the source before generating the final PDF report.",
  },
];

const FEATURES = [
  {
    icon: "◎",
    title: "Evidence-backed findings",
    desc: "Every accepted vulnerability includes a verbatim code snippet pulled directly from the source — no hallucinated findings.",
  },
  {
    icon: "◈",
    title: "Confidence scoring",
    desc: "Each finding is rated 0–100% confidence so you can prioritize which vulnerabilities to fix first.",
  },
  {
    icon: "◻",
    title: "PDF export",
    desc: "Every analysis run produces a clean, formatted PDF report ready to share with your team or attach to a ticket.",
  },
];

/* ── Component ───────────────────────────────────────────────────────────── */

export default function HeroPage() {
  const navigate = useNavigate();

  return (
    <div style={{ background: "var(--canvas)" }}>

      {/* ── Hero split ──────────────────────────────────────────────────── */}
      <section style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        padding: "80px 48px",
        position: "relative",
      }}>
        <div
          className="hero-split"
          style={{ maxWidth: 1100, margin: "0 auto", width: "100%" }}
        >
          {/* Left */}
          <div>
            <div style={{
              display: "inline-flex",
              padding: "4px 14px",
              borderRadius: "var(--r-pill)",
              background: "var(--surface-card)",
              fontSize: 12,
              fontWeight: 500,
              color: "var(--muted)",
              marginBottom: 28,
              letterSpacing: "0.06em",
              textTransform: "uppercase",
            }}>
              Security Analysis Platform
            </div>

            <h1 style={{
              fontFamily: "var(--font-display)",
              fontSize: "clamp(52px, 6.5vw, 80px)",
              fontWeight: 400,
              lineHeight: 1.0,
              letterSpacing: "-0.03em",
              color: "var(--ink)",
              marginBottom: 24,
            }}>
              Reporter
            </h1>

            <p style={{
              fontSize: 18,
              color: "var(--muted)",
              lineHeight: 1.65,
              maxWidth: 420,
              marginBottom: 28,
            }}>
              Automated vulnerability detection for C/C++ source code,
              powered by a four-stage AI agent pipeline.
            </p>

            <ul style={{ listStyle: "none", display: "flex", flexDirection: "column", gap: 10, marginBottom: 40 }}>
              {[
                "Evidence-backed findings with confidence scores",
                "Triage → Finding → Verify → Report pipeline",
                "PDF report export for every analysis run",
              ].map((item) => (
                <li key={item} style={{ display: "flex", alignItems: "flex-start", gap: 10, fontSize: 14, color: "var(--body)" }}>
                  <span style={{ color: "var(--success)", fontSize: 13, marginTop: 1, flexShrink: 0 }}>✓</span>
                  {item}
                </li>
              ))}
            </ul>

            <button
              className="btn btn-primary btn-lg"
              onClick={() => navigate("/projects")}
            >
              Open Projects →
            </button>

            <div style={{
              display: "flex",
              gap: 48,
              marginTop: 56,
              paddingTop: 40,
              borderTop: "1px solid var(--hairline)",
            }}>
              {[
                { value: "4",     label: "Agent Stages" },
                { value: "139",   label: "CVE Cases"    },
                { value: "C/C++", label: "Supported"    },
              ].map((s) => (
                <div key={s.label}>
                  <div style={{
                    fontFamily: "var(--font-display)",
                    fontSize: 30, fontWeight: 400,
                    letterSpacing: "-0.02em", color: "var(--ink)", lineHeight: 1.1,
                  }}>
                    {s.value}
                  </div>
                  <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 5, letterSpacing: "0.03em" }}>
                    {s.label}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Right: Terminal */}
          <div style={{
            background: "var(--surface-dark)",
            borderRadius: "var(--r-xl)",
            overflow: "hidden",
            boxShadow: "0 32px 80px rgba(20,20,19,0.20), 0 4px 16px rgba(20,20,19,0.10)",
          }}>
            {/* Title bar */}
            <div style={{
              display: "flex", alignItems: "center", gap: 6,
              padding: "13px 18px",
              background: "var(--surface-dark-elev)",
              borderBottom: "1px solid rgba(255,255,255,0.06)",
            }}>
              <span style={{ width: 12, height: 12, borderRadius: "50%", background: "#ff5f57", display: "inline-block" }} />
              <span style={{ width: 12, height: 12, borderRadius: "50%", background: "#febc2e", display: "inline-block" }} />
              <span style={{ width: 12, height: 12, borderRadius: "50%", background: "#28c840", display: "inline-block" }} />
              <span style={{ marginLeft: 12, fontSize: 12, color: "var(--on-dark-soft)", fontFamily: "var(--font-mono)" }}>
                reporter — analysis
              </span>
            </div>

            {/* Body */}
            <div style={{ padding: "22px 24px 28px", fontFamily: "var(--font-mono)", fontSize: 13, lineHeight: 1.85 }}>
              <div style={{ marginBottom: 16 }}>
                <span style={{ color: "#28c840" }}>$ </span>
                <span style={{ color: "rgba(250,249,245,0.5)" }}>reporter analyze openssl_1.0.2.zip</span>
              </div>

              {STAGES.map(({ label, msg }) => (
                <div key={label} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ color: "#28c840", fontWeight: 500, flexShrink: 0 }}>✓</span>
                  <span style={{ color: "var(--on-dark)", minWidth: 70 }}>{label}</span>
                  <span style={{ color: "var(--on-dark-soft)" }}>{msg}</span>
                </div>
              ))}

              <div style={{ height: 1, background: "rgba(255,255,255,0.07)", margin: "18px 0" }} />

              {FINDINGS.map((f, i) => (
                <div key={i} style={{ marginBottom: 14 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{
                      fontSize: 10, fontWeight: 700, letterSpacing: "0.05em",
                      color: f.color, background: f.bg, padding: "2px 7px", borderRadius: 4, flexShrink: 0,
                    }}>
                      {f.severity}
                    </span>
                    <span style={{ color: "var(--on-dark)", fontSize: 12 }}>{f.title}</span>
                  </div>
                  <div style={{ color: "var(--on-dark-soft)", fontSize: 11, marginTop: 2, paddingLeft: 2 }}>
                    {f.file} · {f.line} · {f.conf} confidence
                  </div>
                </div>
              ))}

              <div style={{ height: 1, background: "rgba(255,255,255,0.07)", margin: "14px 0" }} />

              <div style={{ fontSize: 12, color: "var(--on-dark-soft)" }}>
                <span style={{ color: "#28c840" }}>✓</span>
                {"  "}3 findings across 12 files{"  ·  "}
                <span style={{ color: "var(--on-dark)" }}>report_20250511.pdf</span>
              </div>
            </div>
          </div>
        </div>

        {/* Scroll hint */}
        <div style={{
          position: "absolute",
          bottom: 32,
          left: "50%",
          transform: "translateX(-50%)",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: 6,
          color: "var(--muted-soft)",
          fontSize: 11,
          letterSpacing: "0.06em",
          textTransform: "uppercase",
        }}>
          <span>Scroll</span>
          <span style={{ fontSize: 16 }}>↓</span>
        </div>
      </section>

      {/* ── How it works ────────────────────────────────────────────────── */}
      <section style={{ background: "var(--surface-card)", padding: "96px 48px" }}>
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>
          {/* Section header */}
          <div style={{ marginBottom: 64 }}>
            <p style={{
              fontSize: 12, fontWeight: 500, letterSpacing: "0.1em",
              textTransform: "uppercase", color: "var(--primary)", marginBottom: 12,
            }}>
              The Pipeline
            </p>
            <h2 style={{
              fontFamily: "var(--font-display)",
              fontSize: "clamp(32px, 4vw, 48px)",
              fontWeight: 400,
              letterSpacing: "-0.02em",
              color: "var(--ink)",
              lineHeight: 1.1,
              maxWidth: 560,
              marginBottom: 16,
            }}>
              Four agents working in sequence
            </h2>
            <p style={{ fontSize: 16, color: "var(--muted)", maxWidth: 480, lineHeight: 1.65 }}>
              Each stage is handled by a specialized AI agent that passes its output to the next — ensuring nothing is missed.
            </p>
          </div>

          {/* Steps grid */}
          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: 2,
          }}>
            {PIPELINE.map((step, i) => (
              <div key={step.num} style={{ display: "flex", gap: 0 }}>
                <div style={{
                  background: "var(--canvas)",
                  borderRadius: "var(--r-lg)",
                  padding: "28px 28px 32px",
                  flex: 1,
                  position: "relative",
                }}>
                  {/* Step number */}
                  <div style={{
                    fontFamily: "var(--font-display)",
                    fontSize: 42,
                    fontWeight: 400,
                    letterSpacing: "-0.03em",
                    color: "var(--hairline)",
                    lineHeight: 1,
                    marginBottom: 20,
                    userSelect: "none",
                  }}>
                    {step.num}
                  </div>

                  {/* Connector line */}
                  {i < PIPELINE.length - 1 && (
                    <div style={{
                      position: "absolute",
                      top: 44,
                      right: -10,
                      width: 20,
                      height: 1,
                      background: "var(--hairline)",
                      zIndex: 1,
                    }} />
                  )}

                  <h3 style={{
                    fontSize: 16,
                    fontWeight: 600,
                    color: "var(--ink)",
                    marginBottom: 10,
                  }}>
                    {step.name}
                  </h3>
                  <p style={{ fontSize: 14, color: "var(--muted)", lineHeight: 1.65 }}>
                    {step.desc}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── What's in every report ──────────────────────────────────────── */}
      <section style={{ background: "var(--canvas)", padding: "96px 48px" }}>
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>
          <div style={{ marginBottom: 64 }}>
            <p style={{
              fontSize: 12, fontWeight: 500, letterSpacing: "0.1em",
              textTransform: "uppercase", color: "var(--primary)", marginBottom: 12,
            }}>
              Output
            </p>
            <h2 style={{
              fontFamily: "var(--font-display)",
              fontSize: "clamp(32px, 4vw, 48px)",
              fontWeight: 400,
              letterSpacing: "-0.02em",
              color: "var(--ink)",
              lineHeight: 1.1,
              maxWidth: 480,
              marginBottom: 16,
            }}>
              What's in every report
            </h2>
            <p style={{ fontSize: 16, color: "var(--muted)", maxWidth: 440, lineHeight: 1.65 }}>
              Every analysis run produces a structured report you can act on immediately.
            </p>
          </div>

          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
            gap: 16,
          }}>
            {FEATURES.map((f) => (
              <div key={f.title} style={{
                background: "var(--surface-card)",
                borderRadius: "var(--r-lg)",
                padding: "32px",
              }}>
                <div style={{
                  fontSize: 22,
                  color: "var(--primary)",
                  marginBottom: 20,
                  opacity: 0.7,
                }}>
                  {f.icon}
                </div>
                <h3 style={{
                  fontSize: 17,
                  fontWeight: 500,
                  color: "var(--ink)",
                  marginBottom: 12,
                  letterSpacing: "-0.01em",
                }}>
                  {f.title}
                </h3>
                <p style={{ fontSize: 14, color: "var(--muted)", lineHeight: 1.7 }}>
                  {f.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA band (dark) ─────────────────────────────────────────────── */}
      <section style={{
        background: "var(--surface-dark)",
        padding: "96px 48px",
        textAlign: "center",
      }}>
        <div style={{ maxWidth: 560, margin: "0 auto" }}>
          <h2 style={{
            fontFamily: "var(--font-display)",
            fontSize: "clamp(32px, 4vw, 48px)",
            fontWeight: 400,
            letterSpacing: "-0.02em",
            color: "var(--on-dark)",
            lineHeight: 1.1,
            marginBottom: 20,
          }}>
            Start your first analysis
          </h2>
          <p style={{
            fontSize: 16,
            color: "var(--on-dark-soft)",
            lineHeight: 1.65,
            marginBottom: 36,
          }}>
            Upload a ZIP archive of C/C++ source code and get a full vulnerability report in minutes.
          </p>
          <button
            className="btn btn-primary btn-lg"
            onClick={() => navigate("/projects")}
            style={{ borderRadius: "var(--r-md)" }}
          >
            Open Projects →
          </button>
        </div>
      </section>

    </div>
  );
}
