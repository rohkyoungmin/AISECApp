import { Link, useMatch } from "react-router-dom";

export default function Header() {
  const onProjects = useMatch("/projects/*");

  return (
    <header className="top-nav">
      <div className="top-nav-inner">
        <Link to="/" className="top-nav-logo">Reporter</Link>
        <nav className="top-nav-links">
          <Link to="/projects" className={`nav-link ${onProjects ? "active" : ""}`}>
            Projects
          </Link>
        </nav>
      </div>
    </header>
  );
}
