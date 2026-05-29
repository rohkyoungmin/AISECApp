import { Link, useMatch } from "react-router-dom";

export default function Header() {
  const onProjects = useMatch("/projects/*");

  return (
    <header className="header">
      <Link to="/" className="header-logo">AISEC</Link>
      <nav className="header-nav">
        <Link to="/projects" className={onProjects ? "active" : ""}>
          Projects
        </Link>
      </nav>
    </header>
  );
}
