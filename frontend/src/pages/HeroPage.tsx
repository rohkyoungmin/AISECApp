import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

const LINES = [
  { text: "$ reporter analyze linux-kernel.zip", type: "cmd" },
  { text: "[TRIAGE]    Scanning 1,247 source files...",  type: "info" },
  { text: "[TRIAGE]    21 high-risk patterns detected",  type: "info" },
  { text: "[FINDING]   Analyzing memory safety...",      type: "info" },
  { text: "[FINDING]   Overflow candidate: ext4.c:1847", type: "warn" },
  { text: "[VERIFY]    Querying NVD CVE database...",    type: "info" },
  { text: "[VERIFY]    CVE-2024-1086   CVSS 7.8 HIGH",  type: "info" },
  { text: "[REPORT]    Generating security report...",   type: "info" },
  { text: "[DONE]      3 critical  5 high  9 medium",   type: "done" },
];

export default function HeroPage() {
  const navigate = useNavigate();
  const [count, setCount] = useState(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let n = 0;

    function tick() {
      n += 1;
      setCount(n);
      if (n < LINES.length) {
        timerRef.current = setTimeout(tick, n === 1 ? 480 : 400);
      } else {
        timerRef.current = setTimeout(() => {
          n = 0;
          setCount(0);
          timerRef.current = setTimeout(tick, 800);
        }, 3800);
      }
    }

    timerRef.current = setTimeout(tick, 700);
    return () => { if (timerRef.current) clearTimeout(timerRef.current); };
  }, []);

  return (
    <div className="hero">
      <div className="hero-grid" />

      <div className="hero-split">
        {/* Left: intro */}
        <div className="hero-content">
          <h1 className="hero-title">Reporter</h1>
          <p className="hero-subtitle">AI-Powered C/C++ Vulnerability Detection</p>

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
              <span className="hero-stat-value">NVD</span>
              <span className="hero-stat-label">CVE Database</span>
            </div>
          </div>
        </div>

        {/* Right: Mac terminal */}
        <div className="hero-terminal">
          <div className="terminal-bar">
            <span className="terminal-dot td-red" />
            <span className="terminal-dot td-yellow" />
            <span className="terminal-dot td-green" />
            <span className="terminal-title">reporter — bash</span>
          </div>
          <div className="terminal-body">
            {LINES.slice(0, count).map((line, i) => (
              <div key={i} className={`terminal-line tl-${line.type}`}>
                {line.text}
              </div>
            ))}
            <span className="terminal-cursor" />
          </div>
        </div>
      </div>

      <div style={{
        position: "absolute", bottom: 28, left: 0, right: 0,
        textAlign: "center", fontFamily: "var(--mono)", fontSize: 11,
        color: "var(--muted-soft)", letterSpacing: "0",
      }}>
        Triage · Finding · Verification · Report
      </div>
    </div>
  );
}
