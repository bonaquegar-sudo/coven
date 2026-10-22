import { useEffect, useRef, useState } from "react";
import { ArrowBarLeft, Close, Hash, Plus, Search } from "pixelarticons/react";
import { AGENTS, API_URL, PROVIDERS, SUBSCRIPTIONS, useCoven, type AgentName, type LLM } from "./store";
import { AgentAvatar, Px } from "./icons";
import PixelLogo from "./PixelLogo";

const DOT = { idle: "bg-white/15", thinking: "bg-violet-400 animate-pulse", tool: "bg-emerald-400 animate-pulse" };
const TIP = { idle: "en espera", thinking: "pensando…", tool: "usando herramienta" };

const item = "flex w-full items-center gap-2.5 px-3 py-1.5 text-left text-ink hover:bg-white/[0.02]";
const section = "px-3 pb-1 pt-5 text-[11px] text-muted/80";

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
    <aside className="flex w-60 shrink-0 animate-fade flex-col border-r border-white/[0.06] bg-panel">
      <div className="flex items-center justify-between px-3 pb-3 pt-3.5">
        <PixelLogo cell={2.6} spin={busy} />
        <button onClick={() => s.set({ sidebarOpen: false })} aria-label="Ocultar barra lateral" className="p-1 text-muted hover:text-ink">
          <Px icon={ArrowBarLeft} />
        </button>
      </div>

      <div className="divide-y divide-white/[0.06] border-y border-white/[0.06]">
        <label className="flex items-center gap-2.5 px-3 py-2 text-muted" title="Ctrl K">
          <Px icon={Search} size={14} />
          <input
            ref={search}
            value={s.query}
            onChange={(e) => s.set({ query: e.target.value })}
            placeholder="Buscar en el canal"
            className="min-w-0 flex-1 bg-transparent text-ink outline-none placeholder:text-muted"
          />
          {s.query && (
            <button onClick={() => s.set({ query: "" })} aria-label="Limpiar búsqueda" className="hover:text-ink">
              <Px icon={Close} size={14} />
            </button>
          )}
        </label>
        <button onClick={s.reset} className={`${item} py-2`}>
          <Px icon={Plus} className="text-emerald-400" /> Nueva sesión
        </button>
      </div>

      <div className="flex-1 overflow-y-auto pb-2">
        {s.channels.length > 0 && <h2 className={section}>Canales</h2>}
        {s.channels.length === 0 && s.socket && [70, 55, 62].map((w) => <div key={w} className="skeleton mx-3 my-2.5 h-3" style={{ width: `${w}%` }} />)}
        {s.channels.map((c, i) => (
          <button
            key={c}
            onClick={() => s.open(c)}
            style={{ animationDelay: `${i * 40}ms` }}
            className={`${item} animate-fade-up ${s.active === c ? "bg-white/[0.04] text-white" : ""} ${s.unread[c] ? "font-semibold" : ""}`}
          >
            <Px icon={Hash} size={14} className={s.active === c ? "text-emerald-400" : "text-muted"} /> {c}
            {!!s.unread[c] && <span className="ml-auto tabular-nums text-[11px] text-emerald-300">{s.unread[c]}</span>}
          </button>
        ))}

        <h2 className={section}>Agentes</h2>
        {(Object.keys(AGENTS) as AgentName[]).map((name) => {
          const st = s.agents[name];
          return (
            <button key={name} title={`${TIP[st.status]} · clic para mencionar a @${name}`} onClick={() => s.set({ draft: `${s.draft}@${name} ` })} className={item}>
              <AgentAvatar name={name} size={20} />
              <span className="min-w-0 flex-1 truncate">
                {name}
                {st.status === "tool" && st.detail && <span className="ml-2 text-[11px] text-muted">{st.detail}</span>}
              </span>
              <span className={`size-1.5 shrink-0 rounded-full ${DOT[st.status]}`} />
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
  const field = "w-full border-b border-white/[0.08] bg-transparent py-1.5 text-ink outline-none transition-colors focus:border-emerald-600/60";
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
    <div className="fixed inset-0 z-20 grid animate-fade place-items-center bg-black/60 p-4" onClick={close}>
      <form
        onClick={(e) => e.stopPropagation()}
        onSubmit={(e) => {
          e.preventDefault();
          setLLM(form);
          close();
        }}
        className="w-full max-w-md animate-pop space-y-4 border border-white/[0.06] bg-panel p-5"
      >
        <div className="flex items-center justify-between">
          <h2 className="font-semibold text-white">Proveedor LLM</h2>
          <button type="button" onClick={close} aria-label="Cerrar" className="p-1 text-muted hover:text-ink">
            <Px icon={Close} />
          </button>
        </div>
        <section>
          <div className="pb-1 text-[11px] text-muted">Tu suscripción, sin API key</div>
          <div className="divide-y divide-white/[0.06] border-y border-white/[0.06]">
            {SUBSCRIPTIONS.map((s) => {
              const st = clis?.[s.id];
              const on = form.provider === s.id;
              return (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => setForm({ ...form, provider: s.id, model: "" })}
                  aria-pressed={on}
                  className={`flex w-full items-center gap-3 px-3 py-2.5 text-left hover:bg-white/[0.02] active:scale-100 ${on ? "text-white" : "text-ink"}`}
                >
                  <span className={`size-1.5 rounded-full ${on ? "bg-emerald-400" : "bg-white/15"}`} />
                  <span className="font-semibold">{s.name}</span>
                  <span className="text-[11px] text-muted">
                    {s.plan} · {s.cli}
                    {st && !st.installed && " · no instalado"}
                  </span>
                </button>
              );
            })}
          </div>
        </section>

        <section>
          <div className="pb-1 text-[11px] text-muted">Con API key</div>
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            {PROVIDERS.map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => setForm({ ...form, provider: p })}
                className={`text-xs ${form.provider === p ? "text-white underline underline-offset-4" : "text-muted hover:text-ink"}`}
              >
                {p}
              </button>
            ))}
          </div>
        </section>

        {sub && (
          <p className={`text-[11px] leading-relaxed ${cli && !cli.installed ? "text-amber-200" : "text-muted"}`}>
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
        <label className="block text-xs text-muted">
          Modelo
          <input
            value={form.model}
            onChange={(e) => setForm({ ...form, model: e.target.value })}
            placeholder={sub ? `vacío = el que use ${sub.cli}` : "vacío = modelo por defecto"}
            className={field}
          />
        </label>
        {!local && !sub && (
          <label className="block text-xs text-muted">
            API key, solo en memoria
            <input type="password" autoComplete="off" value={form.api_key} onChange={(e) => setForm({ ...form, api_key: e.target.value })} className={field} />
          </label>
        )}
        {!sub && (
          <label className="block text-xs text-muted">
            URL base, {local ? "por defecto http://localhost:11434" : "opcional"}
            <input value={form.base_url} onChange={(e) => setForm({ ...form, base_url: e.target.value })} className={field} />
          </label>
        )}
        <button className="w-full rounded-md bg-emerald-600 py-2 font-medium text-white hover:bg-emerald-500">Guardar</button>
      </form>
    </div>
  );
}
