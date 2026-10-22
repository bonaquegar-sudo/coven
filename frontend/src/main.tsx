import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "highlight.js/styles/github-dark.css";
import "./index.css";
import Sidebar, { SettingsModal } from "./Sidebar";
import Chat from "./Chat";
import Inspector from "./Inspector";
import TopBar from "./TopBar";
import { useCoven } from "./store";

function App() {
  const { inspectorOpen, settingsOpen, socket, messages } = useCoven();
  return (
    <div className="flex h-screen flex-col bg-carbon text-ink">
      <TopBar />
      <div className="flex min-h-0 flex-1">
        <Sidebar />
        <Chat />
        {inspectorOpen && (socket || messages.length > 0) && <Inspector />}
      </div>
      {settingsOpen && <SettingsModal />}
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
