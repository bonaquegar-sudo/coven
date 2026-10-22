import { useState } from "react";
import { Bug, Check, ChevronRight, Code, Globe, Key, Package, Search, Shield, Terminal, TestTube, Tools, Undo } from "pixelarticons/react";
import { useCoven, type Finding, type FindingStatus, type InspectorTab, type LogEntry, type Severity } from "./store";
import { AgentAvatar, Px, type IconType } from "./icons";

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
// Severity is coloured text, never a box inside the text.
export const SEV_TEXT: Record<Severity, string> = {
  CRITICAL: "text-red-400",
  HIGH: "text-orange-400",
  MEDIUM: "text-amber-300",
  LOW: "text-sky-300",
};
// Lifecycle order; FALSE_POSITIVE sits outside the pipeline.
const PIPELINE: FindingStatus[] = ["DETECTED", "CONFIRMED_BY_QA", "PATCHED", "VERIFIED"];
const STATUS: Record<FindingStatus, { label: string; tone: string; bar: string }> = {
  DETECTED: { label: "detectado", tone: "text-ink", bar: "bg-zinc-500" },
  CONFIRMED_BY_QA: { label: "confirmado", tone: "text-red-300", bar: "bg-red-400" },
  PATCHED: { label: "parcheado", tone: "text-amber-300", bar: "bg-amber-400" },
  VERIFIED: { label: "verificado", tone: "text-emerald-300", bar: "bg-emerald-400" },
  FALSE_POSITIVE: { label: "falso positivo", tone: "text-muted", bar: "bg-white/15" },
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

// Flat design: full-width rows split by hairlines; no boxes around items.
const row = "block w-full px-3 py-2.5 text-left hover:bg-white/[0.02] active:scale-100";
const toggle = (on: boolean) => `text-[11px] transition-colors ${on ? "text-ink underline underline-offset-4" : "text-muted hover:text-ink"}`;
const clock = (ts: number) => new Date(ts * 1000).toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const duration = (ms?: number) => (ms == null ? "" : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`);

// Split a multi-file unified diff into one chunk per file.
function splitDiff(diff: string) {
  return diff
    .split(/^(?=--- )/m)
    .filter((c) => c.startsWith("--- "))
    .map((chunk) => ({ path: chunk.match(/^\+\+\+ b\/(.+)$/m)?.[1] ?? "?", lines: chunk.split("\n") }));
}

function SkeletonRow({ lines = 2 }: { lines?: number }) {
  return (
    <div className="animate-fade space-y-2 px-3 py-2.5">
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} className="skeleton h-3" style={{ width: `${88 - i * 22}%` }} />
      ))}
    </div>
  );
}

const Empty = ({ text }: { text: string }) => <p className="animate-fade px-3 pt-3 text-muted">{text}</p>;

/** DETECTED → CONFIRMED → PATCHED → VERIFIED as one row: segmented bar + counters that filter the list. */
function Lifecycle({ findings }: { findings: Finding[] }) {
  const { findingFilter, set } = useCoven();
  const count = (s: FindingStatus) => findings.filter((f) => f.status === s).length;
  const real = findings.filter((f) => f.status !== "FALSE_POSITIVE").length;
  const pick = (status: FindingStatus) => set({ findingFilter: { ...findingFilter, status: findingFilter.status === status ? null : status } });

  return (
    <div className="space-y-2 border-b border-white/[0.06] px-3 py-2.5">
      <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-zinc-800">
        {PIPELINE.map((s) => (
          <div key={s} className={`h-full transition-[width] duration-500 ${STATUS[s].bar}`} style={{ width: `${real ? (count(s) / real) * 100 : 0}%` }} />
        ))}
      </div>
      <div className="flex items-center gap-3 text-[11px]">
        {PIPELINE.map((s) => (
          <button key={s} onClick={() => pick(s)} aria-pressed={findingFilter.status === s} className={toggle(findingFilter.status === s)}>
            <span className={`tabular-nums ${count(s) ? STATUS[s].tone : "text-muted/50"}`}>{count(s)}</span> {STATUS[s].label}
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
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-white/[0.06] px-3 py-2">
      {SEVERITIES.map((s) => (
        <button key={s} onClick={() => setF({ severity: f.severity === s ? null : s })} aria-pressed={f.severity === s} className={toggle(f.severity === s)}>
          <span className={`tabular-nums ${SEV_TEXT[s]}`}>{findings.filter((x) => x.severity === s && isOpen(x)).length}</span> {s.toLowerCase()}
        </button>
      ))}
      <button onClick={() => setF({ status: f.status === "OPEN" ? null : "OPEN" })} aria-pressed={f.status === "OPEN"} className={toggle(f.status === "OPEN")}>
        abiertos
      </button>
      {fp > 0 && (
        <button onClick={() => setF({ status: f.status === "FALSE_POSITIVE" ? null : "FALSE_POSITIVE" })} aria-pressed={f.status === "FALSE_POSITIVE"} className={toggle(f.status === "FALSE_POSITIVE")}>
          {fp} falsos +
        </button>
      )}
      {(f.severity || f.status) && (
        <button onClick={() => set({ findingFilter: { severity: null, status: null } })} className="ml-auto text-[11px] text-muted hover:text-ink">
          limpiar
        </button>
      )}
    </div>
  );
}

function FindingRow({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  const set = useCoven((s) => s.set);
  const src = SOURCE[f.source] ?? { icon: Shield, label: f.source };
  const draft = (text: string) => set({ draft: text, active: "general" });
  const where = f.file_path ? ` en ${f.file_path}${f.line_number ? `:${f.line_number}` : ""}` : "";
  const dim = f.status === "FALSE_POSITIVE" || f.status === "VERIFIED";

  return (
    <article className={`${dim ? "opacity-60 hover:opacity-100" : ""} transition-opacity`}>
      <button onClick={() => setOpen(!open)} aria-expanded={open} className={`${row} space-y-1`}>
        <div className="flex items-center gap-2 whitespace-nowrap text-[11px]">
          <span className={`font-semibold ${SEV_TEXT[f.severity] ?? SEV_TEXT.LOW}`}>{f.severity.toLowerCase()}</span>
          <span className="tabular-nums text-muted">{f.id}</span>
          <span title={src.label} className="text-muted/70">
            <Px icon={src.icon} size={11} />
          </span>
          <span className={`ml-auto shrink-0 ${STATUS[f.status]?.tone ?? ""}`}>{STATUS[f.status]?.label ?? f.status}</span>
        </div>
        <h3 className={`leading-snug text-white ${f.status === "FALSE_POSITIVE" ? "line-through decoration-white/30" : ""}`}>{f.title}</h3>
        <div className="flex items-center gap-2 text-[11px]">
          <span className="shrink-0 text-muted">{f.standard}</span>
          {f.file_path && (
            <span className="min-w-0 truncate text-sky-300/80">
              {f.file_path}
              {f.line_number ? `:${f.line_number}` : ""}
            </span>
          )}
          <Px icon={ChevronRight} size={12} className={`ml-auto text-muted transition-transform ${open ? "rotate-90" : ""}`} />
        </div>
      </button>

      {open && (
        <div className="animate-fade space-y-2.5 px-3 pb-3">
          {f.endpoint && <div className="text-[11px] text-muted">endpoint <span className="text-ink">{f.endpoint}</span></div>}
          {f.empirical_evidence && (
            <pre className="max-h-48 overflow-auto whitespace-pre-wrap bg-black/25 px-2.5 py-2 text-[11px] leading-relaxed text-ink/80">{f.empirical_evidence}</pre>
          )}
          {f.fix && <p className="text-xs text-emerald-300/90">→ {f.fix}</p>}
          {f.history?.length > 0 && (
            <ol className="space-y-0.5 border-l border-white/[0.08] pl-3 text-[11px] text-muted">
              {f.history.map((h, j) => <li key={j}>{h}</li>)}
            </ol>
          )}
          {isOpen(f) && (
            <div className="flex gap-4 text-[11px]">
              {f.status !== "PATCHED" && (
                <button onClick={() => draft(`@Fixer corrige ${f.id}: ${f.title}${where}`)} className="flex items-center gap-1.5 text-amber-300 hover:text-amber-200">
                  <Px icon={Tools} size={12} /> Pedir a Fixer
                </button>
              )}
              <button onClick={() => draft(`@QARunner verifica ${f.id}${f.endpoint ? ` (${f.endpoint})` : ""}: ${f.title}`)} className="flex items-center gap-1.5 text-emerald-300 hover:text-emerald-200">
                <Px icon={TestTube} size={12} /> Verificar con QARunner
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
    return scanning ? <div className="divide-y divide-white/[0.06]">{[2, 3, 2].map((n, i) => <SkeletonRow key={i} lines={n} />)}</div> : <Empty text="Sin hallazgos todavía." />;

  const shown = findings
    .filter((f) => (!flt.severity || f.severity === flt.severity) && (!flt.status || (flt.status === "OPEN" ? isOpen(f) : f.status === flt.status)))
    .sort((a, b) => Number(!isOpen(a)) - Number(!isOpen(b)) || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));

  return (
    <>
      <Lifecycle findings={findings} />
      <Filters findings={findings} />
      <div className="divide-y divide-white/[0.06]">
        {shown.map((f) => <FindingRow key={f.id} f={f} />)}
        {scanning && <SkeletonRow />}
      </div>
      {!shown.length && <Empty text="Ningún hallazgo con estos filtros." />}
    </>
  );
}

function LogRow({ l }: { l: LogEntry }) {
  const [open, setOpen] = useState(!l.ok);
  const state = l.running ? "ejecutando" : l.kind === "test" ? (l.ok ? "pass" : "fail") : l.ok ? duration(l.ms) : "error";
  const args = Object.entries(l.args ?? {}).filter(([, v]) => v !== "" && v != null);
  const summary = l.kind === "test" ? l.output.split("\n", 1)[0] : l.summary;

  return (
    <div>
      <button onClick={() => !l.running && setOpen(!open)} aria-expanded={open} className={row}>
        <div className="flex items-center gap-2 text-xs">
          <Px icon={toolIcon(l)} size={12} className={l.running ? "animate-pulse text-emerald-300" : l.ok ? "text-muted" : "text-red-300"} />
          <span className="min-w-0 flex-1 truncate text-ink">{l.title}</span>
          <span className={`tabular-nums text-[11px] ${l.running ? "text-emerald-300" : l.ok ? "text-muted" : "text-red-400"}`}>{state}</span>
        </div>
        {args.length > 0 && (
          <div className="mt-0.5 truncate pl-5 text-[11px] text-muted/80">
            {args.map(([k, v]) => (
              <span key={k} className="mr-2">
                <span className="text-muted/60">{k}=</span>
                {String(v)}
              </span>
            ))}
          </div>
        )}
        <div className="mt-0.5 flex items-center gap-2 pl-5 text-[11px]">
          {l.running ? <span className="skeleton h-2.5 w-2/3" /> : <span className={`min-w-0 flex-1 truncate ${l.ok ? "text-ink/80" : "text-red-300"}`}>{summary}</span>}
          <span className="ml-auto flex shrink-0 items-center gap-1 text-muted/70">
            <AgentAvatar name={l.agent} size={14} /> {clock(l.ts)}
          </span>
        </div>
      </button>
      {open && !l.running && (
        <pre className="max-h-80 animate-fade overflow-auto whitespace-pre-wrap bg-black/25 px-3 py-2.5 text-[11px] leading-relaxed text-ink/80">{l.output}</pre>
      )}
    </div>
  );
}

function Console() {
  const { logs, agents } = useCoven();
  const [kind, setKind] = useState<"all" | "tool" | "test">("all");
  const busy = Object.values(agents).some((a) => a.status !== "idle");
  if (!logs.length) return busy ? <SkeletonRow lines={3} /> : <Empty text="Aún no se han ejecutado escáneres ni tests." />;
  const shown = logs.filter((l) => kind === "all" || l.kind === kind).reverse(); // newest first
  const running = logs.filter((l) => l.running).length;

  return (
    <>
      <div className="flex items-center gap-3 border-b border-white/[0.06] px-3 py-2">
        {(
          [
            ["all", "todo"],
            ["tool", "escáneres"],
            ["test", "tests"],
          ] as const
        ).map(([k, label]) => (
          <button key={k} onClick={() => setKind(k)} aria-pressed={kind === k} className={toggle(kind === k)}>
            {label} <span className="tabular-nums opacity-70">{logs.filter((l) => k === "all" || l.kind === k).length}</span>
          </button>
        ))}
        {running > 0 && <span className="ml-auto text-[11px] text-emerald-300">{running} en curso</span>}
      </div>
      <div className="divide-y divide-white/[0.06]">
        {shown.map((l, i) => <LogRow key={l.id ?? `${l.ts}-${i}`} l={l} />)}
      </div>
    </>
  );
}

function Diff() {
  const { diff, fileAction, agents } = useCoven();
  const files = splitDiff(diff);
  const busy = agents.Fixer.status !== "idle";
  if (!files.length && !busy) return <Empty text="Fixer no ha modificado ningún archivo." />;
  return (
    <div className="divide-y divide-white/[0.06]">
      {files.map((f) => (
        <section key={f.path}>
          <div className="flex items-center gap-3 px-3 py-2">
            <span className="flex-1 truncate text-xs text-ink">{f.path}</span>
            <button onClick={() => fileAction("accept", f.path)} className="flex items-center gap-1 text-[11px] text-emerald-300 hover:text-emerald-200">
              <Px icon={Check} size={12} /> Aceptar
            </button>
            <button onClick={() => fileAction("revert", f.path)} className="flex items-center gap-1 text-[11px] text-red-300 hover:text-red-200">
              <Px icon={Undo} size={12} /> Revertir
            </button>
          </div>
          <pre className="max-h-96 overflow-auto bg-black/25 py-2 text-[11px] leading-relaxed">
            {f.lines.slice(2).map((l, i) => (
              <div
                key={i}
                className={`px-3 ${l.startsWith("+") ? "bg-emerald-500/10 text-emerald-300" : l.startsWith("-") ? "bg-red-500/10 text-red-300" : l.startsWith("@@") ? "text-violet-400" : "text-muted"}`}
              >
                {l || " "}
              </div>
            ))}
          </pre>
        </section>
      ))}
      {busy && <SkeletonRow lines={4} />}
    </div>
  );
}

export default function Inspector() {
  const { findings, logs, diff, inspectorTab: tab, set } = useCoven();
  const running = logs.some((l) => l.running);
  const tabs: { id: InspectorTab; label: string; count: number }[] = [
    { id: "findings", label: "Hallazgos", count: findings.filter(isOpen).length },
    { id: "console", label: "Consola", count: logs.length },
    { id: "diff", label: "Diff", count: splitDiff(diff).length },
  ];

  return (
    <aside className="flex w-80 shrink-0 animate-fade flex-col border-l border-white/[0.06] bg-panel xl:w-[26rem]">
      <div role="tablist" className="flex border-b border-white/[0.06] px-1">
        {tabs.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => set({ inspectorTab: t.id })}
            className={`-mb-px flex items-center gap-1.5 border-b px-2.5 py-2.5 text-xs active:scale-100 ${tab === t.id ? "border-ink text-white" : "border-transparent text-muted hover:text-ink"}`}
          >
            {t.label}
            {t.id === "console" && running ? (
              <span className="size-1.5 animate-pulse rounded-full bg-emerald-400" />
            ) : (
              t.count > 0 && <span className="tabular-nums text-muted">{t.count}</span>
            )}
          </button>
        ))}
      </div>
      <div key={tab} className="flex-1 animate-fade overflow-y-auto pb-4">
        {tab === "findings" ? <Findings /> : tab === "console" ? <Console /> : <Diff />}
      </div>
    </aside>
  );
}
