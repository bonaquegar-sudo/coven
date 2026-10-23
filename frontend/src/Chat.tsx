import { Fragment, useEffect, useRef } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeHighlight from "rehype-highlight";
import { ArrowBarRight, ArrowUp, Check, Close, Folder } from "pixelarticons/react";
import { AGENTS, needsKey, useCoven, type AgentName, type LogEntry, type Message } from "./store";
import { AgentAvatar, Px } from "./icons";
import { toolIcon } from "./Inspector";
import PixelLogo from "./PixelLogo";
import PixelField from "./PixelField";

const MENTION = new RegExp(`@(${Object.keys(AGENTS).join("|")})\\b`, "g");
const WIN_PATH = /\b[A-Za-z]:\\[^\s`*|<>"()]+/g; // plain-text Windows paths, wrapped as code so they become pills
const LOCAL_PATH = /^([A-Za-z]:[\\/]|~\/|\/(Users|home|mnt|var|tmp)\/)/;
const GROUP_WINDOW = 5 * 60; // seconds: consecutive messages by the same author collapse into one block
const day = (ts: number) => new Date(ts * 1000).toDateString();
const time = (ts: number) => new Date(ts * 1000).toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit" });
const longDate = (ts: number) => new Date(ts * 1000).toLocaleDateString("es-ES", { day: "numeric", month: "long", year: "numeric" });
const nameColor = (author: string) => AGENTS[author as AgentName]?.color.split(" ")[1] ?? (author === "system" ? "text-amber-300" : "text-ink");
const displayName = (author: string) => (author === "user" ? "tú" : author === "system" ? "sistema" : author);
const tail = (p: string) => p.split(/[\\/]/).filter(Boolean).slice(-2).join("/");

// Long local path → compact pill with the last two folders; the full path stays in the tooltip.
function PathPill({ path }: { path: string }) {
  return (
    <span title={path} className="rounded bg-white/[0.05] px-1.5 py-0.5 font-mono text-xs text-zinc-300">
      {tail(path)}
    </span>
  );
}

// @Agent → coloured link, plain Windows paths → inline code; fenced and inline code are left alone.
const prepare = (md: string) =>
  md
    .split(/(```[\s\S]*?```|`[^`\n]*`)/)
    .map((part, i) => (i % 2 ? part : part.replace(MENTION, "[@$1](#mention-$1)").replace(WIN_PATH, "`$&`")))
    .join("");

// undefined = not the desktop app; null = the user cancelled the dialog.
async function pickFolder(): Promise<string | null | undefined> {
  const { isTauri } = await import("@tauri-apps/api/core");
  if (!isTauri()) return undefined;
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
            href?.startsWith("#mention-") ? (
              <span className={`font-semibold ${nameColor(href.slice(9))}`}>{children}</span>
            ) : (
              <a href={href} target="_blank" rel="noreferrer" className="text-emerald-400 underline underline-offset-2">
                {children}
              </a>
            ),
          code: ({ className, children, ...rest }) => {
            const text = String(children);
            return !className && LOCAL_PATH.test(text) && !text.includes("\n") ? <PathPill path={text} /> : <code className={className} {...rest}>{children}</code>;
          },
        }}
      >
        {prepare(text)}
      </ReactMarkdown>
    </div>
  );
}

function Divider({ label, accent }: { label: string; accent?: boolean }) {
  return (
    <div className={`my-4 flex animate-fade items-center gap-3 px-4 text-[11px] ${accent ? "text-red-400" : "text-muted"}`}>
      <span className={`h-px flex-1 ${accent ? "bg-red-500/60" : "bg-white/[0.06]"}`} />
      {label}
      {accent && <span className="h-px w-6 bg-red-500/60" />}
    </div>
  );
}

// Message group header: avatar centred on the name line; the body sits under the name.
function Head({ author, children }: { author: string; children?: React.ReactNode }) {
  return (
    <div className="flex items-center gap-3">
      <AgentAvatar name={author} size={28} />
      <span className={`font-semibold ${nameColor(author)}`}>{displayName(author)}</span>
      {children}
    </div>
  );
}

const KIND = { questions: "Preguntas antes de empezar", plan: "Plan", approval: "Aprobación" } as const;

// TechLead's approval request: one click answers it (the reply is a normal chat message, so text works too).
function ApprovalButtons() {
  const send = useCoven((s) => s.send);
  return (
    <div className="mt-2 flex gap-4 pl-10 text-xs">
      <button onClick={() => send("aprobar")} className="flex items-center gap-1.5 rounded-md bg-emerald-600 px-3 py-1.5 font-medium text-white hover:bg-emerald-500">
        <Px icon={Check} size={12} /> Aprobar
      </button>
      <button onClick={() => send("saltar")} className="text-muted hover:text-ink">
        Saltar Fixer
      </button>
    </div>
  );
}

function Row({ m, head, waiting }: { m: Message; head: boolean; waiting?: boolean }) {
  const flagged = m.author === "system" || (waiting && m.kind !== "plan");
  return (
    <div className={`group relative animate-fade-up px-4 py-0.5 hover:bg-white/[0.02] ${head ? "mt-3.5" : ""} ${flagged ? "border-l-2 border-amber-400/80" : "border-l-2 border-transparent"}`}>
      {head ? (
        <Head author={m.author}>
          <span className="text-[11px] text-muted">{time(m.ts)}</span>
        </Head>
      ) : (
        <span className="absolute left-4 top-0.5 w-7 text-center text-[10px] leading-6 text-muted opacity-0 group-hover:opacity-100">{time(m.ts)}</span>
      )}
      {m.final && (
        <div className="mt-1 flex items-center gap-1.5 pl-10 font-semibold text-emerald-400">
          <Px icon={Check} size={14} /> Equipo terminado
        </div>
      )}
      {m.kind && <div className="mt-1 pl-10 text-[11px] font-semibold uppercase tracking-wider text-muted">{KIND[m.kind]}</div>}
      <div className="pl-10">
        <Markdown text={m.content} />
      </div>
      {waiting && m.kind === "approval" && <ApprovalButtons />}
      {waiting && m.kind === "questions" && <p className="pl-10 text-[11px] text-amber-300">Responde en el chat para que TechLead prepare el plan.</p>}
    </div>
  );
}

// A scanner/test run, inlined in the agent's channel as a terminal line; click opens it in the console.
function ToolRow({ l }: { l: LogEntry }) {
  const set = useCoven((s) => s.set);
  const summary = l.kind === "test" ? l.output.split("\n", 1)[0] : l.summary;
  const target = l.args?.endpoint ? ` ${l.args.method ?? "GET"} ${l.args.endpoint}` : "";
  return (
    <button
      onClick={() => set({ inspectorOpen: true, inspectorTab: "console" })}
      className="flex w-full animate-fade items-center gap-2 py-0.5 pl-14 pr-4 text-left text-[11px] hover:bg-white/[0.02] active:scale-100"
    >
      <Px icon={toolIcon(l)} size={12} className={l.running ? "animate-pulse text-emerald-300" : l.ok ? "text-muted" : "text-red-300"} />
      <span className="shrink-0 text-ink">
        {l.kind === "test" ? l.title.replace(/^\$ /, "") : l.title}
        <span className="text-muted">{target}</span>
      </span>
      {l.running ? (
        <span className="text-muted">ejecutando…</span>
      ) : (
        <>
          <span className={`min-w-0 truncate ${l.ok ? "text-muted" : "text-red-300"}`}>→ {summary}</span>
          {l.ms != null && <span className="shrink-0 tabular-nums text-muted/60">{l.ms < 1000 ? `${l.ms}ms` : `${(l.ms / 1000).toFixed(1)}s`}</span>}
        </>
      )}
    </button>
  );
}

function WorkingRow({ name, detail }: { name: AgentName; detail: string }) {
  return (
    <div className="mt-3.5 animate-fade px-4" aria-label={`${name} está trabajando`}>
      <Head author={name}>
        <span className="truncate text-[11px] text-muted">{detail}</span>
      </Head>
      <div className="mt-2 space-y-2 pl-10">
        {[86, 70, 48].map((w) => (
          <div key={w} className="skeleton h-3" style={{ width: `${w}%` }} />
        ))}
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

function RepoField() {
  const { projectPath, project, projectError, set } = useCoven();
  const checked = projectPath.trim() && !projectError.startsWith("backend");
  return (
    <div className="flex items-center gap-2 border-b border-white/[0.06] py-2.5">
      <button
        onClick={async () => {
          const path = await pickFolder();
          if (path) set({ projectPath: path });
          else if (path === undefined) alert("El selector de carpetas solo está disponible en la app de escritorio. Escribe la ruta.");
        }}
        aria-label="Examinar carpetas"
        className="text-muted hover:text-ink"
      >
        <Px icon={Folder} size={14} />
      </button>
      <input
        id="repo-input"
        value={projectPath}
        onChange={(e) => set({ projectPath: e.target.value })}
        placeholder="C:\ruta\a\mi-proyecto"
        aria-label="Ruta del repositorio"
        spellCheck={false}
        className="min-w-0 flex-1 bg-transparent text-ink outline-none placeholder:text-muted/60"
      />
      {checked &&
        (project ? (
          <span title="Repositorio encontrado" className="text-emerald-400">
            <Px icon={Check} size={14} />
          </span>
        ) : (
          projectError && (
            <span title={projectError} className="text-red-400">
              <Px icon={Close} size={14} />
            </span>
          )
        ))}
    </div>
  );
}

// Start options, remembered between sessions.
function StartOptions() {
  const { prefs, setPrefs } = useCoven();
  const opts: [keyof typeof prefs, string, string][] = [
    ["plan", "Plan antes de empezar", "TechLead hace preguntas si falta información y publica un plan antes de tocar nada"],
    ["approveFixes", "Aprobar cambios de Fixer", "El equipo se detiene antes de que Fixer modifique código hasta que apruebes"],
    ["onlyChanges", "Solo archivos cambiados", "Analiza solo lo que cambia respecto a main según git (más rápido y barato)"],
  ];
  return (
    <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-[11px]">
      {opts.map(([k, label, tip]) => (
        <button key={k} title={tip} onClick={() => setPrefs({ [k]: !prefs[k] })} aria-pressed={prefs[k]} className={`flex items-center gap-1.5 ${prefs[k] ? "text-ink" : "text-muted hover:text-ink"}`}>
          <span className={`grid size-3 place-items-center rounded-sm border ${prefs[k] ? "border-emerald-500 bg-emerald-600 text-white" : "border-white/20"}`}>
            {prefs[k] && <Px icon={Check} size={9} />}
          </span>
          {label}
        </button>
      ))}
    </div>
  );
}

function Composer({ hero }: { hero?: boolean }) {
  const s = useCoven();
  const launch = useLaunch();
  const submit = () => (s.socket ? s.send(s.draft) : launch(s.draft));
  return (
    <div className={`flex items-end gap-2 rounded-lg border border-white/[0.08] bg-card px-3 py-2 transition-colors focus-within:border-white/20 ${hero ? "mt-3" : ""}`}>
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
        placeholder={hero ? "Pide algo al equipo o pulsa enter para el escaneo completo" : `Mensaje a #${s.active}`}
        aria-label="Mensaje"
        className="max-h-48 w-full resize-none bg-transparent leading-[1.6] text-ink caret-emerald-400 outline-none placeholder:text-muted/70 [field-sizing:content]"
      />
      <button
        onClick={submit}
        disabled={!!s.socket && !s.draft.trim()}
        aria-label={s.socket ? "Enviar" : "Iniciar sesión"}
        className="grid size-7 shrink-0 place-items-center rounded-md bg-emerald-600 text-white hover:bg-emerald-500 disabled:bg-white/[0.06] disabled:text-muted"
      >
        <Px icon={ArrowUp} size={14} />
      </button>
    </div>
  );
}

export default function Chat() {
  const { active, messages, logs, socket, agents, query, newSince, sidebarOpen, projectPath, running, set } = useCoven();
  const last = messages.filter((m) => m.channel === "general").at(-1); // a questions/approval message is open until answered
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
  }, [timeline.length, active, here.length, running]); // running: the approval buttons appear when a run ends

  const showSidebar = !sidebarOpen && (
    <button onClick={() => set({ sidebarOpen: true })} aria-label="Mostrar barra lateral" className="p-1 text-muted hover:text-ink">
      <Px icon={ArrowBarRight} />
    </button>
  );

  if (!socket && !messages.length)
    return (
      <main className="relative flex min-w-0 flex-1 flex-col overflow-y-auto px-4">
        <PixelField />
        <div className="absolute left-3 top-3 z-10">{showSidebar}</div>
        <div className="relative m-auto w-full max-w-2xl animate-fade-up py-10">
          <div className="mb-10 flex justify-center">
            <PixelLogo big cell={14} className="h-auto max-w-full" />
          </div>
          <RepoField />
          <Composer hero />
          <StartOptions />
        </div>
      </main>
    );

  return (
    <main className="flex min-w-0 flex-1 flex-col">
      <header className="flex items-center gap-2 border-b border-white/[0.06] px-3 py-2">
        {showSidebar}
        <span className="font-semibold text-ink">#{active}</span>
        {projectPath && <PathPill path={projectPath} />}
      </header>

      <div className="flex-1 overflow-x-hidden overflow-y-auto">
        <div key={active} className="animate-fade pb-4 pt-2">
          {timeline.length === 0 && here.length === 0 && (
            <p className="px-4 pt-4 text-muted">{q ? `Sin resultados para "${query}".` : "Esperando mensajes…"}</p>
          )}
          {timeline.map((item, i) => {
            if ("l" in item) return <ToolRow key={item.l.id ?? `t${i}`} l={item.l} />;
            const m = item.m;
            const before = timeline[i - 1];
            const prev = before && "m" in before ? before.m : undefined; // a tool run breaks the group
            const newDay = !prev || day(prev.ts) !== day(m.ts);
            const isNew = m.id === newSince;
            const head = newDay || isNew || m.final || !prev || prev.author !== m.author || m.ts - prev.ts > GROUP_WINDOW;
            return (
              <Fragment key={m.id}>
                {newDay && (prev || i === 0) && <Divider label={longDate(m.ts)} />}
                {isNew && <Divider label="nuevos" accent />}
                <Row m={m} head={!!head} waiting={!running && m.id === last?.id && !!m.kind} />
              </Fragment>
            );
          })}
          {!q && here.map((n) => <WorkingRow key={n} name={n} detail={agents[n].status === "tool" ? agents[n].detail : "pensando…"} />)}
          <div ref={end} />
        </div>
      </div>

      <div className="px-4 pb-3">
        <div className="flex h-6 items-center gap-3 text-[11px] text-muted">
          {working
            .filter((n) => !here.includes(n))
            .map((n) => (
              <button key={n} onClick={() => useCoven.getState().open(AGENTS[n].channel)} className="flex animate-fade items-center gap-1.5 hover:text-ink">
                <AgentAvatar name={n} size={16} /> {n} en #{AGENTS[n].channel}
              </button>
            ))}
        </div>
        <Composer />
      </div>
    </main>
  );
}
