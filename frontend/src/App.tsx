import { Routes, Route } from "react-router-dom";
import HeroPage from "./pages/HeroPage";
import ProjectsPage from "./pages/ProjectsPage";
import ProjectDetailPage from "./pages/ProjectDetailPage";
import ProgressPage from "./pages/ProgressPage";
import ReportPage from "./pages/ReportPage";

export default function App() {
  return (
    <Routes>
      <Route path="/"                                              element={<HeroPage />} />
      <Route path="/projects"                                      element={<ProjectsPage />} />
      <Route path="/projects/:projectId"                           element={<ProjectDetailPage />} />
      <Route path="/projects/:projectId/jobs/:jobId"               element={<ProgressPage />} />
      <Route path="/projects/:projectId/reports/:reportId"         element={<ReportPage />} />
    </Routes>
  );
}
