import { useEffect, useRef, useState } from "react";
import { ArrowBarLeft, Close, Hash, Layout, Plus, Search, Sliders } from "pixelarticons/react";
import { AGENTS, API_URL, PROVIDERS, SUBSCRIPTIONS, useCoven, type AgentName, type LLM } from "./store";
import { AgentAvatar, Px } from "./icons";
import PixelLogo from "./PixelLogo";

const STATUS = {
  idle: { dot: "bg-white/15", label: "idle" },
  thinking: { dot: "bg-violet-400 animate-pulse", label: "pensando…" },
  tool: { dot: "bg-emerald-400 animate-pulse", label: "usando herramienta" },
};

const item = "flex w-full items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-left text-ink hover:bg-white/[0.05]";
const section = "px-2.5 pb-1.5 pt-5 text-[11px] uppercase tracking-wider text-muted/80";

export default function Sidebar() {
  const s = useCoven();
  const search = useRef<HTMLInputElement>(null);
  const busy = Object.values(s.agents).some((a) => a.status !== "idle");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        useCoven.getState().set({ sidebarOpen: true });
        setTimeout(() => search.current?.focus());
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (!s.sidebarOpen) return null;

  return (
    <aside className="flex w-64 shrink-0 animate-fade flex-col border-r border-edge bg-panel">
      <div className="flex items-center justify-between px-3 pb-3 pt-3.5">
        <PixelLogo cell={2.6} spin={busy} className="ml-1.5" />
        <button onClick={() => s.set({ sidebarOpen: false })} aria-label="Ocultar barra lateral" className="rounded-md p-1.5 text-muted hover:bg-white/5 hover:text-ink">
          <Px icon={ArrowBarLeft} />
        </button>
      </div>

      <div className="px-2">
        <label className="flex items-center gap-2 rounded-lg border border-transparent bg-white/[0.04] px-2.5 py-1.5 text-muted transition-colors focus-within:border-edge">
          <Px icon={Search} size={14} />
          <input
            ref={search}
            value={s.query}
            onChange={(e) => s.set({ query: e.target.value })}
            placeholder="Buscar en el canal"
            className="min-w-0 flex-1 bg-transparent text-ink outline-none placeholder:text-muted"
          />
          {s.query ? (
            <button onClick={() => s.set({ query: "" })} aria-label="Limpiar búsqueda" className="hover:text-ink">
              <Px icon={Close} size={14} />
            </button>
          ) : (
            <kbd className="rounded border border-edge px-1 text-[10px]">Ctrl K</kbd>
          )}
        </label>

        <nav className="mt-2 space-y-0.5">
          <button onClick={s.reset} className={`${item} bg-white/[0.05]`}>
            <Px icon={Plus} className="text-emerald-400" /> Nueva sesión
          </button>
          <button onClick={() => s.set({ inspectorOpen: !s.inspectorOpen })} className={item}>
            <Px icon={Layout} className="text-muted" /> Inspector
          </button>
          <button onClick={() => s.set({ settingsOpen: true })} className={item}>
            <Px icon={Sliders} className="text-muted" /> Proveedor LLM
          </button>
        </nav>
      </div>

      <div className="flex-1 overflow-y-auto px-2 pb-2">
        <h2 className={section}>Canales</h2>
        {s.channels.length === 0 &&
          (s.socket ? (
            [70, 55, 62].map((w) => <div key={w} className="skeleton mx-2.5 my-2.5 h-3" style={{ width: `${w}%` }} />)
          ) : (
            <p className="px-2.5 text-xs text-muted/70">TechLead los creará al iniciar.</p>
          ))}
        {s.channels.map((c, i) => (
          <button
            key={c}
            onClick={() => s.open(c)}
            style={{ animationDelay: `${i * 40}ms` }}
            className={`${item} animate-fade-up ${s.active === c ? "bg-white/[0.07] text-white" : ""} ${s.unread[c] ? "font-semibold" : ""}`}
          >
            <Px icon={Hash} size={14} className={s.active === c ? "text-emerald-400" : "text-muted"} /> {c}
            {!!s.unread[c] && <span className="ml-auto animate-pop rounded bg-emerald-500/15 px-1.5 text-[10px] text-emerald-300">{s.unread[c]}</span>}
          </button>
        ))}

        <h2 className={section}>Agentes</h2>
        {(Object.keys(AGENTS) as AgentName[]).map((name) => {
          const st = s.agents[name];
          return (
            <button key={name} title={`Mencionar a @${name}`} onClick={() => s.set({ draft: `${s.draft}@${name} ` })} className={item}>
              <AgentAvatar name={name} size={26} />
              <span className="min-w-0 flex-1">
                <span className="block leading-tight">{name}</span>
                <span className={`block truncate text-[11px] ${st.status === "idle" ? "text-muted/70" : "text-muted"}`}>
                  {st.status === "tool" && st.detail ? st.detail : STATUS[st.status].label}
                </span>
              </span>
              <span className={`size-1.5 rounded-full ${STATUS[st.status].dot}`} />
            </button>
          );
        })}
      </div>
    </aside>
  );
}

export function SettingsModal() {
  const { llm, setLLM, set } = useCoven();
  const [form, setForm] = useState<LLM>(llm);
  const close = () => set({ settingsOpen: false });
  const field = "w-full rounded-lg border border-edge bg-panel px-2.5 py-2 text-ink outline-none transition-colors focus:border-emerald-600/60";
  const local = form.provider === "ollama";
  const sub = SUBSCRIPTIONS.find((s) => s.id === form.provider);
  // CLI install state per subscription provider, from the backend (null = backend unreachable / loading)
  const [clis, setClis] = useState<Record<string, { installed: boolean; login: string }> | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("keydown", onKey);
    fetch(`${API_URL}/providers`)
      .then((r) => r.json())
      .then(setClis)
      .catch(() => setClis(null));
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const cli = sub && clis?.[sub.id];

  return (
    <div className="fixed inset-0 z-20 grid animate-fade place-items-center bg-black/60 p-4 backdrop-blur-[2px]" onClick={close}>
      <form
        onClick={(e) => e.stopPropagation()}
        onSubmit={(e) => {
          e.preventDefault();
          setLLM(form);
          close();
        }}
        className="w-full max-w-md animate-pop space-y-4 rounded-2xl border border-edge bg-card p-5 shadow-2xl shadow-black/40"
      >
        <div className="flex items-center justify-between">
          <h2 className="flex items-center gap-2 font-semibold text-white">
            <Px icon={Sliders} className="text-emerald-400" /> Proveedor LLM
          </h2>
          <button type="button" onClick={close} aria-label="Cerrar" className="rounded-md p-1 text-muted hover:bg-white/5 hover:text-ink">
            <Px icon={Close} />
          </button>
        </div>
        <section className="space-y-1.5">
          <div className="text-[10px] uppercase tracking-wider text-muted">Tu suscripción · sin API key</div>
          <div className="grid grid-cols-3 gap-1.5">
            {SUBSCRIPTIONS.map((s) => {
              const st = clis?.[s.id];
              const on = form.provider === s.id;
              return (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => setForm({ ...form, provider: s.id, model: "" })}
                  aria-pressed={on}
                  className={`rounded-lg border p-2.5 text-left transition-colors active:scale-100 ${
                    on ? "border-emerald-500/50 bg-emerald-500/[0.08]" : "border-edge bg-panel hover:border-white/15"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className={`font-semibold ${on ? "text-white" : "text-ink"}`}>{s.name}</span>
                    {st && <span className={`size-1.5 rounded-full ${st.installed ? "bg-emerald-400" : "bg-white/20"}`} title={st.installed ? "CLI instalado" : "CLI no instalado"} />}
                  </div>
                  <div className="text-[10px] text-muted">{s.plan}</div>
                  <div className="mt-1 text-[10px] text-muted/70">vía {s.cli}</div>
                </button>
              );
            })}
          </div>
        </section>

        <section className="space-y-1.5">
          <div className="text-[10px] uppercase tracking-wider text-muted">API key</div>
          <div className="grid grid-cols-5 gap-1 rounded-lg bg-panel p-1">
            {PROVIDERS.map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => setForm({ ...form, provider: p })}
                className={`rounded-md py-1.5 text-[11px] ${form.provider === p ? "bg-white/10 text-white" : "text-muted hover:text-ink"}`}
              >
                {p}
              </button>
            ))}
          </div>
        </section>

        {sub && (
          <p className={`rounded-lg border px-3 py-2 text-[11px] leading-relaxed ${cli && !cli.installed ? "border-amber-500/30 bg-amber-500/[0.06] text-amber-200" : "border-edge bg-panel text-muted"}`}>
            {cli && !cli.installed ? (
              <>No encuentro {sub.cli} en este equipo: {cli.login}.</>
            ) : (
              <>
                Coven usa tu sesión de <span className="text-ink">{sub.cli}</span> en este equipo; no guarda ni ve ningún token. Si aún no has
                entrado: {cli?.login ?? "inicia sesión en el CLI"}.
              </>
            )}
          </p>
        )}
        <label className="block space-y-1.5 text-xs text-muted">
          Modelo
          <input
            value={form.model}
            onChange={(e) => setForm({ ...form, model: e.target.value })}
            placeholder={sub ? `vacío = el que use ${sub.cli}` : "vacío = modelo por defecto"}
            className={field}
          />
        </label>
        {!local && !sub && (
          <label className="block space-y-1.5 text-xs text-muted">
            API key <span className="opacity-60">· solo en memoria</span>
            <input type="password" autoComplete="off" value={form.api_key} onChange={(e) => setForm({ ...form, api_key: e.target.value })} className={field} />
          </label>
        )}
        {!sub && <label className="block space-y-1.5 text-xs text-muted">
          URL base <span className="opacity-60">· {local ? "por defecto http://localhost:11434" : "opcional"}</span>
          <input value={form.base_url} onChange={(e) => setForm({ ...form, base_url: e.target.value })} className={field} />
        </label>}
        <button className="w-full rounded-lg bg-emerald-600 py-2 font-medium text-white hover:bg-emerald-500">Guardar</button>
      </form>
    </div>
  );
}
