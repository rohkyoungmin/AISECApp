import { useNavigate } from "react-router-dom";

export default function HeroPage() {
  const navigate = useNavigate();

  return (
    <div className="hero">
      <div className="hero-grid" />

      <div className="hero-content">
        <span className="hero-icon">⬡</span>
        <h1 className="hero-title">AISEC</h1>
        <p className="hero-subtitle">AI-Powered Vulnerability Detection Engine</p>

        <button className="hero-cta" onClick={() => navigate("/projects")}>
          Start Analysis
        </button>

        <div className="hero-stats">
          <div className="hero-stat">
            <span className="hero-stat-value">4</span>
            <span className="hero-stat-label">Agent Stages</span>
          </div>
          <div className="hero-stat">
            <span className="hero-stat-value">139</span>
            <span className="hero-stat-label">CVE Cases</span>
          </div>
          <div className="hero-stat">
            <span className="hero-stat-value">C/C++</span>
            <span className="hero-stat-label">Languages</span>
          </div>
        </div>
      </div>

      <div
        style={{
          position: "absolute",
          bottom: 28,
          left: 0,
          right: 0,
          textAlign: "center",
          fontFamily: "var(--mono)",
          fontSize: 11,
          color: "var(--muted-soft)",
          letterSpacing: "0.12em",
        }}
      >
        Triage · Finding · Verification · Report
      </div>
    </div>
  );
}
