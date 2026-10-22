import { useState } from "react";
import { Bug, Check, ChevronRight, Code, Globe, Key, Package, Search, Shield, Terminal, TestTube, Tools, Undo } from "pixelarticons/react";
import { useCoven, type Finding, type FindingStatus, type InspectorTab, type LogEntry, type Severity } from "./store";
import { AgentAvatar, Px, type IconType } from "./icons";

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
export const SEV_STYLE: Record<Severity, string> = {
  CRITICAL: "bg-red-500/15 text-red-300 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  MEDIUM: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  LOW: "bg-sky-500/15 text-sky-300 border-sky-500/30",
};
// Lifecycle order; FALSE_POSITIVE sits outside the pipeline.
const PIPELINE: FindingStatus[] = ["DETECTED", "CONFIRMED_BY_QA", "PATCHED", "VERIFIED"];
const STATUS: Record<FindingStatus, { label: string; tone: string; dot: string }> = {
  DETECTED: { label: "detectado", tone: "text-ink", dot: "bg-white/40" },
  CONFIRMED_BY_QA: { label: "confirmado", tone: "text-red-300", dot: "bg-red-400" },
  PATCHED: { label: "parcheado", tone: "text-amber-300", dot: "bg-amber-400" },
  VERIFIED: { label: "verificado", tone: "text-emerald-300", dot: "bg-emerald-400" },
  FALSE_POSITIVE: { label: "falso positivo", tone: "text-muted", dot: "bg-white/15" },
};
const SOURCE: Record<string, { icon: IconType; label: string }> = {
  osv: { icon: Package, label: "OSV" },
  secrets: { icon: Key, label: "secretos" },
  sast: { icon: Code, label: "SAST" },
  semgrep: { icon: Code, label: "semgrep" },
  dast: { icon: Globe, label: "DAST" },
  reviewer: { icon: Shield, label: "Reviewer" },
};
const TOOL_ICON: Record<string, IconType> = {
  scan_dependencies_osv: Package, scan_secrets: Key, run_sast: Code, map_api_routes: Search,
  verify_endpoint_security: Globe, report_finding: Bug, set_finding_status: Check,
};
export const toolIcon = (l: LogEntry) => (l.kind === "test" ? TestTube : TOOL_ICON[l.title] ?? Terminal);
export const isOpen = (f: Finding) => f.status !== "VERIFIED" && f.status !== "FALSE_POSITIVE";

const card = "animate-fade-up overflow-hidden rounded-xl border border-edge bg-card";
const chip = "rounded-md border px-2 py-1 text-[11px] transition-colors";
const clock = (ts: number) => new Date(ts * 1000).toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const duration = (ms?: number) => (ms == null ? "" : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`);

// Split a multi-file unified diff into one chunk per file.
function splitDiff(diff: string) {
  return diff
    .split(/^(?=--- )/m)
    .filter((c) => c.startsWith("--- "))
    .map((chunk) => ({ path: chunk.match(/^\+\+\+ b\/(.+)$/m)?.[1] ?? "?", lines: chunk.split("\n") }));
}

function SkeletonCard({ lines = 3 }: { lines?: number }) {
  return (
    <div className={`${card} animate-fade space-y-2.5 p-3.5`}>
      <div className="flex gap-2">
        <div className="skeleton h-4 w-14" />
        <div className="skeleton h-4 flex-1" />
      </div>
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} className="skeleton h-3" style={{ width: `${90 - i * 18}%` }} />
      ))}
    </div>
  );
}

const Empty = ({ text }: { text: string }) => (
  <p className="animate-fade px-1 pt-2 text-muted">
    <span className="text-emerald-400">$</span> {text}
  </p>
);

/** DETECTED → CONFIRMED → PATCHED → VERIFIED counts; each stage filters the list. */
function Lifecycle({ findings }: { findings: Finding[] }) {
  const { findingFilter, set } = useCoven();
  const count = (s: FindingStatus) => findings.filter((f) => f.status === s).length;
  const real = findings.filter((f) => f.status !== "FALSE_POSITIVE").length;
  const verified = count("VERIFIED");
  const toggle = (status: FindingStatus) => set({ findingFilter: { ...findingFilter, status: findingFilter.status === status ? null : status } });

  return (
    <div className={`${card} p-3`}>
      <div className="mb-2 flex items-baseline justify-between text-[11px]">
        <span className="uppercase tracking-wider text-muted">Ciclo de vida</span>
        <span className="tabular-nums text-muted">
          <span className="text-emerald-300">{verified}</span>/{real} verificados
        </span>
      </div>
      <div className="mb-3 h-1 overflow-hidden rounded-full bg-white/[0.06]">
        <div className="h-full rounded-full bg-emerald-400 transition-[width] duration-500" style={{ width: `${real ? (verified / real) * 100 : 0}%` }} />
      </div>
      <div className="grid grid-cols-4 gap-1">
        {PIPELINE.map((s, i) => (
          <button
            key={s}
            onClick={() => toggle(s)}
            aria-pressed={findingFilter.status === s}
            className={`relative rounded-lg px-2 py-1.5 text-left transition-colors ${findingFilter.status === s ? "bg-white/[0.08]" : "hover:bg-white/[0.04]"}`}
          >
            <div className={`text-base font-semibold tabular-nums leading-none ${count(s) ? STATUS[s].tone : "text-muted/50"}`}>{count(s)}</div>
            <div className="mt-1 flex items-center gap-1 text-[10px] text-muted">
              <span className={`size-1.5 rounded-full ${STATUS[s].dot}`} />
              {STATUS[s].label}
            </div>
            {i < PIPELINE.length - 1 && <Px icon={ChevronRight} size={10} className="absolute -right-1.5 top-2.5 text-muted/40" />}
          </button>
        ))}
      </div>
    </div>
  );
}

function Filters({ findings }: { findings: Finding[] }) {
  const { findingFilter: f, set } = useCoven();
  const fp = findings.filter((x) => x.status === "FALSE_POSITIVE").length;
  const setF = (p: Partial<typeof f>) => set({ findingFilter: { ...f, ...p } });
  const active = f.severity || f.status;
  return (
    <div className="flex flex-wrap items-center gap-1">
      {SEVERITIES.map((s) => {
        const n = findings.filter((x) => x.severity === s && isOpen(x)).length;
        return (
          <button
            key={s}
            onClick={() => setF({ severity: f.severity === s ? null : s })}
            aria-pressed={f.severity === s}
            className={`${chip} ${f.severity === s ? SEV_STYLE[s] : "border-edge text-muted hover:text-ink"}`}
          >
            <span className="tabular-nums">{n}</span> {s.toLowerCase()}
          </button>
        );
      })}
      <button
        onClick={() => setF({ status: f.status === "OPEN" ? null : "OPEN" })}
        aria-pressed={f.status === "OPEN"}
        className={`${chip} ${f.status === "OPEN" ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300" : "border-edge text-muted hover:text-ink"}`}
      >
        abiertos
      </button>
      {fp > 0 && (
        <button
          onClick={() => setF({ status: f.status === "FALSE_POSITIVE" ? null : "FALSE_POSITIVE" })}
          aria-pressed={f.status === "FALSE_POSITIVE"}
          className={`${chip} ${f.status === "FALSE_POSITIVE" ? "border-white/20 bg-white/[0.06] text-ink" : "border-edge text-muted hover:text-ink"}`}
        >
          {fp} falsos +
        </button>
      )}
      {active && (
        <button onClick={() => set({ findingFilter: { severity: null, status: null } })} className="ml-auto text-[11px] text-muted underline-offset-2 hover:text-ink hover:underline">
          limpiar
        </button>
      )}
    </div>
  );
}

function FindingCard({ f, i }: { f: Finding; i: number }) {
  const [open, setOpen] = useState(false);
  const set = useCoven((s) => s.set);
  const src = SOURCE[f.source] ?? { icon: Shield, label: f.source };
  const draft = (text: string) => set({ draft: text, active: "general" });
  const where = f.file_path ? ` en ${f.file_path}${f.line_number ? `:${f.line_number}` : ""}` : "";
  const dim = f.status === "FALSE_POSITIVE" || f.status === "VERIFIED";

  return (
    <article style={{ animationDelay: `${Math.min(i, 12) * 30}ms` }} className={`${card} ${dim ? "opacity-60 hover:opacity-100" : ""} transition-opacity`}>
      <button onClick={() => setOpen(!open)} aria-expanded={open} className="block w-full space-y-1.5 p-3 text-left hover:bg-white/[0.02] active:scale-100">
        <div className="flex items-center gap-1.5 whitespace-nowrap text-[10px] tracking-wider">
          <span className={`rounded border px-1.5 py-px uppercase ${SEV_STYLE[f.severity] ?? SEV_STYLE.LOW}`}>{f.severity}</span>
          <span className="tabular-nums text-muted">{f.id}</span>
          <span className="flex min-w-0 items-center gap-1 text-muted/80" title={src.label}>
            <Px icon={src.icon} size={11} /> <span className="hidden truncate xl:inline">{src.label}</span>
          </span>
          <span className={`ml-auto flex shrink-0 items-center gap-1 ${STATUS[f.status]?.tone ?? ""}`}>
            <span className={`size-1.5 rounded-full ${STATUS[f.status]?.dot}`} />
            {STATUS[f.status]?.label ?? f.status}
          </span>
        </div>
        <h3 className={`font-semibold leading-snug text-white ${f.status === "FALSE_POSITIVE" ? "line-through decoration-white/30" : ""}`}>{f.title}</h3>
        <div className="flex items-center gap-2 text-[11px]">
          <span className="shrink-0 text-violet-300">{f.standard}</span>
          {f.file_path && (
            <code className="min-w-0 truncate text-sky-300/90">
              {f.file_path}
              {f.line_number ? `:${f.line_number}` : ""}
            </code>
          )}
          <Px icon={ChevronRight} size={12} className={`ml-auto text-muted transition-transform ${open ? "rotate-90" : ""}`} />
        </div>
      </button>

      {open && (
        <div className="animate-fade space-y-2.5 border-t border-edge px-3 pb-3 pt-2.5">
          {f.endpoint && (
            <div className="text-[11px] text-muted">
              endpoint <code className="text-ink">{f.endpoint}</code>
            </div>
          )}
          {f.empirical_evidence && (
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-wider text-muted">Evidencia</div>
              <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded-md bg-black/35 p-2 text-[11px] leading-relaxed text-ink/80">{f.empirical_evidence}</pre>
            </div>
          )}
          {f.fix && <p className="text-xs text-emerald-300/90">→ {f.fix}</p>}
          {f.history?.length > 0 && (
            <ol className="space-y-1 border-l border-edge pl-3 text-[11px] text-muted">
              {f.history.map((h, j) => (
                <li key={j} className="relative">
                  <span className="absolute -left-[15px] top-1.5 size-1.5 rounded-full bg-edge" />
                  {h}
                </li>
              ))}
            </ol>
          )}
          {isOpen(f) && (
            <div className="flex gap-1.5 pt-0.5">
              {f.status !== "PATCHED" && (
                <button onClick={() => draft(`@Fixer corrige ${f.id}: ${f.title}${where}`)} className="flex items-center gap-1.5 rounded-md border border-amber-500/25 px-2 py-1 text-[11px] text-amber-300 hover:bg-amber-500/10">
                  <Px icon={Tools} size={12} /> Pedir a @Fixer
                </button>
              )}
              <button
                onClick={() => draft(`@QARunner verifica ${f.id}${f.endpoint ? ` (${f.endpoint})` : ""}: ${f.title}`)}
                className="flex items-center gap-1.5 rounded-md border border-emerald-500/25 px-2 py-1 text-[11px] text-emerald-300 hover:bg-emerald-500/10"
              >
                <Px icon={TestTube} size={12} /> Verificar con @QARunner
              </button>
            </div>
          )}
        </div>
      )}
    </article>
  );
}

function Findings() {
  const { findings, agents, findingFilter: flt } = useCoven();
  const scanning = agents.CodeScout.status !== "idle" || agents.Reviewer.status !== "idle";
  if (!findings.length)
    return scanning ? (
      <div className="space-y-3">{[3, 2, 3].map((n, i) => <SkeletonCard key={i} lines={n} />)}</div>
    ) : (
      <Empty text="sin hallazgos todavía: CodeScout y Reviewer los registran al escanear" />
    );

  const shown = findings
    .filter((f) => (!flt.severity || f.severity === flt.severity) && (!flt.status || (flt.status === "OPEN" ? isOpen(f) : f.status === flt.status)))
    .sort((a, b) => Number(!isOpen(a)) - Number(!isOpen(b)) || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));

  return (
    <div className="space-y-3">
      <Lifecycle findings={findings} />
      <Filters findings={findings} />
      {shown.map((f, i) => <FindingCard key={f.id} f={f} i={i} />)}
      {!shown.length && <Empty text="ningún hallazgo con estos filtros" />}
      {scanning && <SkeletonCard lines={2} />}
    </div>
  );
}

function LogCard({ l }: { l: LogEntry }) {
  const [open, setOpen] = useState(!l.ok);
  const state = l.running ? "ejecutando" : l.kind === "test" ? (l.ok ? "pass" : "fail") : l.ok ? duration(l.ms) : "error";
  const args = Object.entries(l.args ?? {}).filter(([, v]) => v !== "" && v != null);
  const summary = l.kind === "test" ? l.output.split("\n", 1)[0] : l.summary;

  return (
    <div className={`${card} ${l.running ? "border-emerald-600/30" : !l.ok ? "border-red-500/30" : ""}`}>
      <button onClick={() => !l.running && setOpen(!open)} aria-expanded={open} className="block w-full px-3 py-2 text-left hover:bg-white/[0.02] active:scale-100">
        <div className="flex items-center gap-2 text-xs">
          <span className={`grid size-5 place-items-center rounded ${l.running ? "bg-emerald-500/15 text-emerald-300" : l.ok ? "bg-white/[0.05] text-muted" : "bg-red-500/15 text-red-300"}`}>
            <Px icon={toolIcon(l)} size={12} className={l.running ? "animate-pulse" : ""} />
          </span>
          <span className="min-w-0 flex-1 truncate font-semibold text-ink">{l.title}</span>
          <span className={`tabular-nums ${l.running ? "text-emerald-300" : l.ok ? "text-muted" : "text-red-400"}`}>{state}</span>
        </div>
        {args.length > 0 && (
          <div className="mt-1 truncate pl-7 text-[11px] text-muted/80">
            {args.map(([k, v]) => (
              <span key={k} className="mr-2">
                <span className="text-muted/60">{k}=</span>
                {String(v)}
              </span>
            ))}
          </div>
        )}
        <div className="mt-1 flex items-center gap-2 pl-7 text-[11px]">
          {l.running ? (
            <span className="skeleton h-2.5 w-2/3" />
          ) : (
            <span className={`min-w-0 flex-1 truncate ${l.ok ? "text-ink/80" : "text-red-300"}`}>{summary}</span>
          )}
          <span className="ml-auto flex shrink-0 items-center gap-1 text-muted/70">
            <AgentAvatar name={l.agent} size={14} /> {clock(l.ts)}
          </span>
        </div>
      </button>
      {open && !l.running && (
        <pre className="max-h-80 animate-fade overflow-auto whitespace-pre-wrap border-t border-edge bg-black/35 p-3 text-[11px] leading-relaxed text-ink/80">{l.output}</pre>
      )}
    </div>
  );
}

function Console() {
  const { logs, agents } = useCoven();
  const [kind, setKind] = useState<"all" | "tool" | "test">("all");
  const busy = Object.values(agents).some((a) => a.status !== "idle");
  if (!logs.length) return busy ? <SkeletonCard lines={3} /> : <Empty text="aún no se han ejecutado escáneres ni tests" />;
  const shown = logs.filter((l) => kind === "all" || l.kind === kind).reverse(); // newest first
  const running = logs.filter((l) => l.running).length;

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-1">
        {(
          [
            ["all", "todo"],
            ["tool", "escáneres"],
            ["test", "tests"],
          ] as const
        ).map(([k, label]) => (
          <button
            key={k}
            onClick={() => setKind(k)}
            aria-pressed={kind === k}
            className={`${chip} ${kind === k ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300" : "border-edge text-muted hover:text-ink"}`}
          >
            {label} <span className="tabular-nums opacity-70">{logs.filter((l) => k === "all" || l.kind === k).length}</span>
          </button>
        ))}
        {running > 0 && (
          <span className="ml-auto flex items-center gap-1.5 text-[11px] text-emerald-300">
            <span className="size-1.5 animate-pulse rounded-full bg-emerald-400" /> {running} en curso
          </span>
        )}
      </div>
      {shown.map((l, i) => <LogCard key={l.id ?? `${l.ts}-${i}`} l={l} />)}
    </div>
  );
}

function Diff() {
  const { diff, fileAction, agents } = useCoven();
  const files = splitDiff(diff);
  const busy = agents.Fixer.status !== "idle";
  if (!files.length && !busy) return <Empty text="Fixer no ha modificado ningún archivo" />;
  return (
    <div className="space-y-3">
      {files.map((f) => (
        <div key={f.path} className={card}>
          <div className="flex items-center gap-1 border-b border-edge px-3 py-1.5">
            <code className="flex-1 truncate text-xs text-ink">{f.path}</code>
            <button onClick={() => fileAction("accept", f.path)} className="flex items-center gap-1 rounded-md px-2 py-1 text-[11px] text-emerald-300 hover:bg-emerald-500/10">
              <Px icon={Check} size={12} /> Aceptar
            </button>
            <button onClick={() => fileAction("revert", f.path)} className="flex items-center gap-1 rounded-md px-2 py-1 text-[11px] text-red-300 hover:bg-red-500/10">
              <Px icon={Undo} size={12} /> Revertir
            </button>
          </div>
          <pre className="max-h-96 overflow-auto bg-black/30 py-2 text-[11px] leading-relaxed">
            {f.lines.slice(2).map((l, i) => (
              <div
                key={i}
                className={`px-3 ${
                  l.startsWith("+") ? "bg-emerald-500/10 text-emerald-300" : l.startsWith("-") ? "bg-red-500/10 text-red-300" : l.startsWith("@@") ? "text-violet-400" : "text-muted"
                }`}
              >
                {l || " "}
              </div>
            ))}
          </pre>
        </div>
      ))}
      {busy && <SkeletonCard lines={5} />}
    </div>
  );
}

export default function Inspector() {
  const { findings, logs, diff, inspectorTab: tab, set } = useCoven();
  const running = logs.some((l) => l.running);
  const tabs: { id: InspectorTab; label: string; icon: IconType; count: number }[] = [
    { id: "findings", label: "Hallazgos", icon: Shield, count: findings.filter(isOpen).length },
    { id: "console", label: "Consola", icon: Terminal, count: logs.length },
    { id: "diff", label: "Diff", icon: Code, count: splitDiff(diff).length },
  ];

  return (
    <aside className="flex w-80 shrink-0 animate-fade flex-col border-l border-edge bg-panel xl:w-[26rem]">
      <div role="tablist" className="m-3 grid grid-cols-3 gap-1 rounded-lg bg-white/[0.04] p-1">
        {tabs.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => set({ inspectorTab: t.id })}
            className={`flex min-w-0 items-center justify-center gap-1 rounded-md px-1 py-1.5 text-xs ${
              tab === t.id ? "bg-card text-white shadow-sm shadow-black/30" : "text-muted hover:text-ink"
            }`}
          >
            <Px icon={t.icon} size={14} className={`hidden xl:block ${tab === t.id ? "text-emerald-400" : ""}`} />
            <span className="truncate">{t.label}</span>
            {t.id === "console" && running ? (
              <span className="size-1.5 animate-pulse rounded-full bg-emerald-400" />
            ) : (
              t.count > 0 && <span className="animate-pop rounded bg-emerald-500/15 px-1 text-[10px] tabular-nums text-emerald-300">{t.count}</span>
            )}
          </button>
        ))}
      </div>
      <div key={tab} className="flex-1 animate-fade overflow-y-auto px-3 pb-4">
        {tab === "findings" ? <Findings /> : tab === "console" ? <Console /> : <Diff />}
      </div>
    </aside>
  );
}
