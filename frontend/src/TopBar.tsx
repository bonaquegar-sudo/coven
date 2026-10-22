import { useEffect } from "react";
import { Layout } from "pixelarticons/react";
import { API_URL, providerLabel, useCoven } from "./store";
import { Px } from "./icons";

/** Detects the stack of the chosen repo for the Mission Control card. */
function useProjectCheck() {
  const { projectPath, set } = useCoven();
  useEffect(() => {
    if (!projectPath.trim()) return set({ project: null, projectError: "" });
    const t = setTimeout(() => {
      fetch(`${API_URL}/project?path=${encodeURIComponent(projectPath.trim())}`)
        .then(async (r) => (r.ok ? set({ project: await r.json(), projectError: "" }) : set({ project: null, projectError: "No existe el directorio" })))
        .catch(() => set({ project: null, projectError: "backend no disponible" }));
    }, 400);
    return () => clearTimeout(t);
  }, [projectPath]);
}

export default function TopBar() {
  useProjectCheck();
  const { inspectorOpen, usage, llm, set } = useCoven();
  const agents = Object.entries(usage);
  const sum = (k: "input" | "cache_write" | "cache_read" | "output" | "cost") => agents.reduce((n, [, u]) => n + u[k], 0);
  const tokens = sum("input") + sum("cache_write") + sum("cache_read") + sum("output");
  const kTok = (n: number) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${Math.round(n / 1e3)}k` : `${n}`);
  const usageTitle = agents
    .map(([a, u]) => `${a}: ${u.calls} llamadas · ${kTok(u.input + u.cache_write)} entrada nueva · ${kTok(u.cache_read)} caché · ${kTok(u.output)} salida`)
    .join("\n") + (sum("cost") ? `\n≈ $${sum("cost").toFixed(2)} a precio de API` : "");

  return (
    <header className="flex h-9 shrink-0 items-center gap-3 border-b border-white/[0.06] bg-panel px-3 text-[11px]">
      <div className="ml-auto flex shrink-0 items-center gap-3">
        {tokens > 0 && (
          <span title={usageTitle} className="cursor-help tabular-nums text-muted">
            {kTok(tokens)} tokens · {Math.round((sum("cache_read") / tokens) * 100)}% caché
          </span>
        )}
        <button onClick={() => set({ settingsOpen: true })} title="Cambiar proveedor o modelo" className="text-muted hover:text-ink">
          <span className="text-ink">{llm.model || "modelo por defecto"}</span> · {providerLabel(llm.provider)}
        </button>
        <button
          onClick={() => set({ inspectorOpen: !inspectorOpen })}
          aria-label={inspectorOpen ? "Ocultar inspector" : "Mostrar inspector"}
          aria-pressed={inspectorOpen}
          className={`p-1 ${inspectorOpen ? "text-ink" : "text-muted hover:text-ink"}`}
        >
          <Px icon={Layout} size={14} />
        </button>
      </div>
    </header>
  );
}
