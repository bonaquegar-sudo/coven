import { Fragment, useEffect, useRef } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeHighlight from "rehype-highlight";
import { ArrowBarRight, ArrowUp, Bug, Folder, Search, Shield, TestTube } from "pixelarticons/react";
import { AGENTS, needsKey, providerLabel, useCoven, type AgentName, type LogEntry, type Message } from "./store";
import { AgentAvatar, Px, type IconType } from "./icons";
import { toolIcon } from "./Inspector";
import PixelLogo from "./PixelLogo";
import PixelField from "./PixelField";

const TOPICS: Record<string, string> = {
  general: "coordinación del equipo y peticiones",
  arquitectura: "mapa técnico del proyecto",
  auditoria: "code review y hallazgos",
  tests: "ejecución y propuesta de tests",
  parches: "cambios aplicados y diffs",
};
const MENTION = new RegExp(`@(${Object.keys(AGENTS).join("|")})\\b`, "g");
const GROUP_WINDOW = 5 * 60; // seconds: consecutive messages by the same author collapse into one block
const basename = (p: string) => p.split(/[\\/]/).filter(Boolean).pop() ?? p;
const day = (ts: number) => new Date(ts * 1000).toDateString();
const time = (ts: number) => new Date(ts * 1000).toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit" });
const stamp = (ts: number) => `${new Date(ts * 1000).toLocaleDateString("es-ES")} ${time(ts)}`;
const longDate = (ts: number) => new Date(ts * 1000).toLocaleDateString("es-ES", { day: "numeric", month: "long", year: "numeric" });
const nameColor = (author: string) => AGENTS[author as AgentName]?.color.split(" ")[1] ?? (author === "system" ? "text-amber-300" : "text-ink");
const displayName = (author: string) => (author === "user" ? "tú" : author === "system" ? "sistema" : author);

// Turn @Agent into links (rendered as chips), skipping fenced and inline code.
const withMentions = (md: string) =>
  md.split(/(```[\s\S]*?```|`[^`\n]*`)/).map((part, i) => (i % 2 ? part : part.replace(MENTION, "[@$1](#mention)"))).join("");

async function pickFolder(): Promise<string | null> {
  const { isTauri } = await import("@tauri-apps/api/core");
  if (!isTauri()) return null;
  const { open } = await import("@tauri-apps/plugin-dialog");
  return open({ directory: true });
}

function Markdown({ text }: { text: string }) {
  return (
    <div className="prose-coven">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeHighlight]}
        components={{
          a: ({ href, children }) =>
            href === "#mention" ? (
              <span className="rounded bg-violet-500/15 px-1 text-violet-300">{children}</span>
            ) : (
              <a href={href} target="_blank" rel="noreferrer" className="text-emerald-400 underline underline-offset-2">
                {children}
              </a>
            ),
        }}
      >
        {withMentions(text)}
      </ReactMarkdown>
    </div>
  );
}

function Divider({ label, accent }: { label: string; accent?: boolean }) {
  return (
    <div className={`my-4 flex animate-fade items-center gap-3 px-4 text-[11px] ${accent ? "text-red-400" : "text-muted"}`}>
      <span className={`h-px flex-1 ${accent ? "bg-red-500/60" : "bg-edge"}`} />
      {label}
      {accent && <span className="h-px w-6 bg-red-500/60" />}
    </div>
  );
}

// Discord-style message: avatar + coloured name + timestamp on the first message of a group,
// continuation lines only show their time in the gutter on hover.
function Row({ m, head }: { m: Message; head: boolean }) {
  const agent = AGENTS[m.author as AgentName];
  const flagged = m.author === "system";
  return (
    <div
      className={`group relative animate-fade-up px-4 py-0.5 hover:bg-white/[0.025] ${head ? "mt-3.5 pt-1" : ""} ${
        flagged ? "border-l-2 border-amber-400/80 bg-amber-400/[0.05] hover:bg-amber-400/[0.07]" : "border-l-2 border-transparent"
      }`}
    >
      {head ? (
        <div className="absolute left-4 top-1.5">
          <AgentAvatar name={m.author} size={36} />
        </div>
      ) : (
        <span className="absolute left-4 top-1 w-9 text-center text-[10px] leading-6 text-muted opacity-0 group-hover:opacity-100">{time(m.ts)}</span>
      )}
      <div className="pl-12">
        {head && (
          <div className="flex items-baseline gap-2">
            <span className={`font-semibold ${nameColor(m.author)}`}>{displayName(m.author)}</span>
            {agent && <span className="rounded bg-white/[0.06] px-1 text-[10px] uppercase tracking-wider text-muted">{agent.role}</span>}
            <span className="text-[11px] text-muted">{stamp(m.ts)}</span>
          </div>
        )}
        <Markdown text={m.content} />
      </div>
    </div>
  );
}

// A scanner/test run, inlined in the agent's channel as a terminal line; click opens it in the console.
function ToolRow({ l }: { l: LogEntry }) {
  const set = useCoven((s) => s.set);
  const summary = l.kind === "test" ? l.output.split("\n", 1)[0] : l.summary;
  const target = l.args?.endpoint ? ` ${l.args.method ?? "GET"} ${l.args.endpoint}` : "";
  return (
    <div className="animate-fade px-4 py-0.5">
      <button
        onClick={() => set({ inspectorOpen: true, inspectorTab: "console" })}
        className={`ml-12 flex max-w-[calc(100%-3rem)] items-center gap-2 rounded-md border px-2 py-1 text-left text-[11px] active:scale-100 ${
          l.running ? "border-emerald-600/30 bg-emerald-500/[0.04]" : l.ok ? "border-edge bg-white/[0.02] hover:bg-white/[0.05]" : "border-red-500/30 bg-red-500/[0.05]"
        }`}
      >
        <Px icon={toolIcon(l)} size={12} className={l.running ? "animate-pulse text-emerald-300" : l.ok ? "text-muted" : "text-red-300"} />
        <span className="shrink-0 text-ink">
          <span className="text-emerald-400">❯</span> {l.kind === "test" ? l.title.replace(/^\$ /, "") : l.title}
          <span className="text-muted">{target}</span>
        </span>
        {l.running ? (
          <span className="flex items-center text-muted">
            ejecutando<span className="ml-1 inline-block w-[0.55em] animate-[blink_1s_steps(1)_infinite] bg-emerald-400/80">&nbsp;</span>
          </span>
        ) : (
          <>
            <span className={`min-w-0 truncate ${l.ok ? "text-muted" : "text-red-300"}`}>→ {summary}</span>
            {l.ms != null && <span className="shrink-0 tabular-nums text-muted/60">{l.ms < 1000 ? `${l.ms}ms` : `${(l.ms / 1000).toFixed(1)}s`}</span>}
          </>
        )}
      </button>
    </div>
  );
}

function WorkingRow({ name, detail }: { name: AgentName; detail: string }) {
  return (
    <div className="relative mt-3.5 animate-fade px-4 pt-1" aria-label={`${name} está trabajando`}>
      <div className="absolute left-4 top-1.5">
        <AgentAvatar name={name} size={36} />
      </div>
      <div className="pl-12">
        <div className="flex items-baseline gap-2">
          <span className={`font-semibold ${nameColor(name)}`}>{name}</span>
          <span className="truncate text-[11px] text-muted">
            <span className="text-emerald-400">$</span> {detail}
            <span className="ml-0.5 inline-block w-[0.55em] animate-[blink_1s_steps(1)_infinite] bg-emerald-400/80">&nbsp;</span>
          </span>
        </div>
        <div className="mt-2 space-y-2">
          {[86, 70, 48].map((w) => (
            <div key={w} className="skeleton h-3" style={{ width: `${w}%` }} />
          ))}
        </div>
      </div>
    </div>
  );
}

// Starts a session (optionally with a direct request), pointing at whatever is still missing first.
function useLaunch() {
  const s = useCoven();
  return (request = "") => {
    if (!s.projectPath.trim() || s.projectError) return document.getElementById("repo-input")?.focus();
    if (needsKey(s.llm.provider) && !s.llm.api_key) return s.set({ settingsOpen: true });
    s.start(request);
  };
}

function TargetCard() {
  const { projectPath, project, projectError, set } = useCoven();
  const tile = "flex min-w-0 flex-col gap-2 rounded-xl border border-edge bg-card/70 p-3.5 transition-colors focus-within:border-emerald-600/50";
  const label = "flex items-center justify-between text-[10px] uppercase tracking-wider text-muted";
  const pill = (on: boolean | null, yes: string, no: string) =>
    on === null ? (
      <span className="text-muted/60">—</span>
    ) : (
      <span className={`flex items-center gap-1 normal-case tracking-normal ${on ? "text-emerald-400" : "text-red-400"}`}>
        <span className={`size-1.5 rounded-full ${on ? "bg-emerald-400 shadow-[0_0_6px] shadow-emerald-400/70" : "bg-red-400"}`} />
        {on ? yes : no}
      </span>
    );

  return (
    <div className="mb-3">
      <div className={tile}>
        <div className={label}>
          <span className="flex items-center gap-1.5">
            <Px icon={Folder} size={12} className="text-emerald-400" /> Repositorio local
          </span>
          {pill(projectPath.trim() && !projectError.startsWith("backend") ? !!project : null, "detectado", "no encontrado")}
        </div>
        <div className="flex items-center gap-1.5">
          <input
            id="repo-input"
            value={projectPath}
            onChange={(e) => set({ projectPath: e.target.value })}
            placeholder="C:\ruta\a\mi-proyecto"
            aria-label="Ruta del repositorio"
            spellCheck={false}
            className="min-w-0 flex-1 bg-transparent text-ink outline-none placeholder:text-muted/60"
          />
          <button
            onClick={async () => {
              const path = await pickFolder();
              if (path) set({ projectPath: path });
              else if (path === null) alert("El selector de carpetas solo está disponible en la app de escritorio. Escribe la ruta.");
            }}
            aria-label="Examinar carpetas"
            className="rounded-md p-1 text-muted hover:bg-white/5 hover:text-ink"
          >
            <Px icon={Folder} size={14} />
          </button>
        </div>
        <div className="flex min-h-5 flex-wrap items-center gap-1">
          {project?.stack.map((t, i) => (
            <span key={t} style={{ animationDelay: `${i * 40}ms` }} className="animate-pop rounded border border-emerald-500/25 bg-emerald-500/10 px-1.5 py-px text-[10px] text-emerald-300">
              {t}
            </span>
          ))}
          {project && !project.stack.length && <span className="text-[11px] text-muted">stack no reconocido</span>}
          {!project && <span className={`text-[11px] ${projectError ? "text-red-400" : "text-muted/70"}`}>{projectError || "el stack se detecta al elegir la carpeta"}</span>}
        </div>
      </div>
    </div>
  );
}

const QUICK_ACTIONS: { icon: IconType; title: string; desc: string; tint: string; request: string }[] = [
  { icon: Search, title: "Escaneo completo", desc: "mapa, auditoría y tests", tint: "bg-emerald-500/15 text-emerald-300", request: "" },
  {
    icon: Shield, title: "Auditoría de seguridad", desc: "auth, inyecciones, secretos", tint: "bg-rose-500/15 text-rose-300",
    request: "@Reviewer haz una auditoría de seguridad: autenticación, sesiones, inyecciones, validación de entrada y secretos expuestos.",
  },
  {
    icon: Bug, title: "Dependencias y CVEs", desc: "versiones vulnerables", tint: "bg-violet-500/15 text-violet-300",
    request: "@Reviewer revisa los manifiestos de dependencias y señala versiones con CVEs conocidos, indicando el CVE y la versión segura.",
  },
  {
    icon: TestTube, title: "Ejecutar tests", desc: "compilador y suite", tint: "bg-sky-500/15 text-sky-300",
    request: "@QARunner ejecuta el compilador y la suite de tests y reporta los fallos.",
  },
];

function QuickActions() {
  const launch = useLaunch();
  return (
    <div className="mt-6 grid grid-cols-2 gap-2 md:grid-cols-4">
      {QUICK_ACTIONS.map((a, i) => (
        <button
          key={a.title}
          onClick={() => launch(a.request)}
          style={{ animationDelay: `${120 + i * 50}ms` }}
          className="group flex animate-fade-up flex-col items-start gap-2.5 rounded-xl border border-edge bg-card/50 p-3.5 text-left hover:-translate-y-0.5 hover:border-emerald-600/40 hover:bg-card"
        >
          <span className={`grid size-8 place-items-center rounded-lg ${a.tint}`}>
            <Px icon={a.icon} size={16} />
          </span>
          <span>
            <span className="block font-semibold text-ink">{a.title}</span>
            <span className="block text-[11px] text-muted">{a.desc}</span>
          </span>
        </button>
      ))}
    </div>
  );
}

function Composer({ hero }: { hero?: boolean }) {
  const s = useCoven();
  const launch = useLaunch();
  const submit = () => (s.socket ? s.send(s.draft) : launch(s.draft));
  const model = (
    <button onClick={() => s.set({ settingsOpen: true })} className="rounded-md px-2 py-1 text-xs hover:bg-white/5">
      <span className="text-ink">{s.llm.model || "modelo por defecto"}</span> <span className="text-muted">{providerLabel(s.llm.provider)}</span>
    </button>
  );

  return (
    <div className="w-full">
      <div className="rounded-xl border border-edge bg-card px-3 pb-2 pt-3 shadow-xl shadow-black/25 transition-colors focus-within:border-emerald-600/40">
        <div className="flex gap-2">
          <span className="select-none leading-[1.6] text-emerald-400">❯</span>
          <textarea
            value={s.draft}
            onChange={(e) => s.set({ draft: e.target.value })}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                submit();
              }
            }}
            rows={hero ? 2 : 1}
            placeholder={hero ? "pide algo al equipo, o enter para el escaneo completo" : `mensaje a #${s.active} · @Fixer, @Reviewer…`}
            aria-label="Mensaje"
            className="max-h-48 w-full resize-none bg-transparent leading-[1.6] text-ink caret-emerald-400 outline-none placeholder:text-muted/70 [field-sizing:content]"
          />
        </div>
        <div className="mt-1 flex items-center justify-between">
          {hero ? (
            <span className="px-1 text-[11px] text-muted/70">↵ enviar · ⇧↵ nueva línea</span>
          ) : (
            <span className="flex items-center gap-1.5 px-1 text-[11px] text-muted">
              <Px icon={Folder} size={12} />~/{basename(s.projectPath)}
            </span>
          )}
          <div className="flex items-center gap-1">
            {model}
            <button
              onClick={submit}
              disabled={!!s.socket && !s.draft.trim()}
              aria-label={s.socket ? "Enviar" : "Iniciar sesión"}
              className="grid size-8 place-items-center rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 disabled:bg-white/[0.06] disabled:text-muted"
            >
              <Px icon={ArrowUp} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function Chat() {
  const { active, messages, logs, socket, connected, agents, query, newSince, sidebarOpen, projectPath, set } = useCoven();
  const end = useRef<HTMLDivElement>(null);
  const q = query.trim().toLowerCase();
  const list = messages.filter((m) => m.channel === active && (!q || m.content.toLowerCase().includes(q)));
  // Messages and tool runs of this channel, in time order (tool runs hidden while searching).
  const timeline: ({ m: Message } | { l: LogEntry })[] = [
    ...list.map((m) => ({ m })),
    ...(q ? [] : logs.filter((l) => AGENTS[l.agent as AgentName]?.channel === active).map((l) => ({ l }))),
  ].sort((a, b) => ("m" in a ? a.m.ts : a.l.ts) - ("m" in b ? b.m.ts : b.l.ts));
  const working = (Object.keys(AGENTS) as AgentName[]).filter((n) => agents[n].status !== "idle");
  const here = working.filter((n) => AGENTS[n].channel === active);

  useEffect(() => {
    end.current?.scrollIntoView({ behavior: "smooth" }); // newer browsers return a Promise here; must not leak to React
  }, [timeline.length, active, here.length]);

  const iconBtn = "rounded-md p-1.5 text-muted hover:bg-white/5 hover:text-ink";
  const showSidebar = !sidebarOpen && (
    <button onClick={() => set({ sidebarOpen: true })} aria-label="Mostrar barra lateral" className={iconBtn}>
      <Px icon={ArrowBarRight} />
    </button>
  );

  if (!socket && !messages.length)
    return (
      <main className="relative flex min-w-0 flex-1 flex-col overflow-y-auto px-4">
        <PixelField />
        <div className="absolute left-3 top-3 z-10">{showSidebar}</div>
        <div className="relative m-auto w-full max-w-3xl animate-fade-up py-10">
          <div className="mb-9 flex justify-center">
            <PixelLogo cell={9} className="max-w-full" />
          </div>
          <TargetCard />
          <Composer hero />
          <QuickActions />
        </div>
      </main>
    );

  return (
    <main className="flex min-w-0 flex-1 flex-col">
      <header className="flex items-center gap-2 border-b border-edge/70 px-3 py-2.5">
        {showSidebar}
        <span className="truncate text-muted" title={projectPath}>
          ~/{basename(projectPath)}
        </span>
        <span className="font-semibold text-emerald-400">#{active}</span>
        <span className="hidden truncate text-[11px] text-muted/70 md:inline">// {TOPICS[active]}</span>
        <span className={`ml-auto flex items-center gap-1.5 text-[11px] ${connected ? "text-emerald-400" : "text-muted"}`}>
          <span className={`size-1.5 rounded-full ${connected ? "bg-emerald-400" : "bg-white/20"}`} />
          {connected ? "conectado" : "desconectado"}
        </span>
      </header>

      <div className="flex-1 overflow-x-hidden overflow-y-auto">
        <div key={active} className="animate-fade pb-4 pt-2">
          {timeline.length === 0 && here.length === 0 && (
            <p className="px-4 pt-4 text-muted">
              <span className="text-emerald-400">$</span> {q ? `grep "${query}" → sin resultados` : `tail -f #${active} → esperando mensajes…`}
            </p>
          )}
          {timeline.map((item, i) => {
            if ("l" in item) return <ToolRow key={item.l.id ?? `t${i}`} l={item.l} />;
            const m = item.m;
            const before = timeline[i - 1];
            const prev = before && "m" in before ? before.m : undefined; // a tool run breaks the group
            const newDay = !prev || day(prev.ts) !== day(m.ts);
            const isNew = m.id === newSince;
            const head = newDay || isNew || !prev || prev.author !== m.author || m.ts - prev.ts > GROUP_WINDOW;
            return (
              <Fragment key={m.id}>
                {newDay && (prev || i === 0) && <Divider label={longDate(m.ts)} />}
                {isNew && <Divider label="nuevos" accent />}
                <Row m={m} head={head} />
              </Fragment>
            );
          })}
          {!q && here.map((n) => <WorkingRow key={n} name={n} detail={agents[n].status === "tool" ? agents[n].detail : "pensando…"} />)}
          <div ref={end} />
        </div>
      </div>

      <div className="px-4 pb-4">
        <div className="flex h-7 items-center gap-1.5 text-[11px] text-muted">
          {working
            .filter((n) => !here.includes(n))
            .map((n) => (
              <button key={n} onClick={() => useCoven.getState().open(AGENTS[n].channel)} className="flex animate-fade items-center gap-1.5 rounded-full bg-white/[0.04] py-0.5 pl-0.5 pr-2 hover:bg-white/[0.08]">
                <AgentAvatar name={n} size={18} /> {n} en #{AGENTS[n].channel}
              </button>
            ))}
        </div>
        <Composer />
      </div>
    </main>
  );
}
