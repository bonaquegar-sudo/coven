import { useEffect } from "react";
import { Layout } from "pixelarticons/react";
import { API_URL, useCoven, type Severity } from "./store";
import { Px } from "./icons";
import { SEV_STYLE, isOpen } from "./Inspector";

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
  const { findings, inspectorOpen, usage, set } = useCoven();
  const agents = Object.entries(usage);
  const sum = (k: "input" | "cache_write" | "cache_read" | "output" | "cost") => agents.reduce((n, [, u]) => n + u[k], 0);
  const tokens = sum("input") + sum("cache_write") + sum("cache_read") + sum("output");
  const kTok = (n: number) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${Math.round(n / 1e3)}k` : `${n}`);
  const usageTitle = agents
    .map(([a, u]) => `${a}: ${u.calls} llamadas · ${kTok(u.input + u.cache_write)} entrada nueva · ${kTok(u.cache_read)} caché · ${kTok(u.output)} salida`)
    .join("\n") + (sum("cost") ? `\n≈ $${sum("cost").toFixed(2)} a precio de API` : "");
  const open = findings.filter(isOpen);
  const counts: { label: string; n: number; severity: Severity | null }[] = [
    { label: "Critical", n: open.filter((f) => f.severity === "CRITICAL").length, severity: "CRITICAL" },
    { label: "High", n: open.filter((f) => f.severity === "HIGH").length, severity: "HIGH" },
    { label: "CVEs", n: open.filter((f) => f.source === "osv").length, severity: null },
  ];
  const verified = findings.filter((f) => f.status === "VERIFIED").length;
  const show = (severity: Severity | null) =>
    set({ inspectorOpen: true, inspectorTab: "findings", findingFilter: { severity, status: "OPEN" } });

  return (
    <header className="flex h-10 shrink-0 items-center gap-4 border-b border-edge bg-panel px-3 text-[11px]">
      <div className="ml-auto flex shrink-0 items-center gap-1.5">
        {tokens > 0 && (
          <span title={usageTitle} className="mr-1 cursor-help tabular-nums text-muted">
            {kTok(tokens)} tokens · {Math.round((sum("cache_read") / tokens) * 100)}% caché
          </span>
        )}
        {verified > 0 && <span className="mr-1 tabular-nums text-emerald-400">{verified} verificados</span>}
        {counts.map((c) => (
          <button
            key={c.label}
            onClick={() => show(c.severity)}
            title={`Ver hallazgos abiertos${c.severity ? ` ${c.severity}` : " de dependencias"}`}
            className={`rounded border px-1.5 py-0.5 tabular-nums transition-colors active:scale-100 ${
              c.n ? (c.severity ? SEV_STYLE[c.severity] : "border-violet-500/30 bg-violet-500/15 text-violet-300") : "border-edge text-muted hover:text-ink"
            }`}
          >
            {c.n} {c.label}
          </button>
        ))}
        <button
          onClick={() => set({ inspectorOpen: !inspectorOpen })}
          aria-label={inspectorOpen ? "Cerrar inspector" : "Abrir inspector"}
          aria-pressed={inspectorOpen}
          className={`ml-1 rounded p-1 ${inspectorOpen ? "bg-white/[0.07] text-emerald-400" : "text-muted hover:bg-white/5 hover:text-ink"}`}
        >
          <Px icon={Layout} size={14} />
        </button>
      </div>
    </header>
  );
}
