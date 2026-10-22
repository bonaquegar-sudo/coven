/// <reference types="vite/client" />
import { create } from "zustand";
import { Crown, Map, Shield, TestTube, Tools } from "pixelarticons/react";

export const AGENTS = {
  TechLead: { icon: Crown, channel: "general", color: "bg-violet-500/15 text-violet-300" },
  CodeScout: { icon: Map, channel: "arquitectura", color: "bg-sky-500/15 text-sky-300" },
  Reviewer: { icon: Shield, channel: "auditoria", color: "bg-rose-500/15 text-rose-300" },
  QARunner: { icon: TestTube, channel: "tests", color: "bg-emerald-500/15 text-emerald-300" },
  Fixer: { icon: Tools, channel: "parches", color: "bg-amber-500/15 text-amber-300" },
} as const;
export type AgentName = keyof typeof AGENTS;
export const PROVIDERS = ["openrouter", "anthropic", "openai", "gemini", "ollama"] as const;
// Your own subscription, through the vendor's official CLI (no API key).
export const SUBSCRIPTIONS = [
  { id: "claude-sub", name: "Claude", plan: "Pro / Max", cli: "Claude Code" },
  { id: "chatgpt-sub", name: "ChatGPT", plan: "Plus / Pro", cli: "Codex CLI" },
  { id: "gemini-sub", name: "Google", plan: "Gemini", cli: "Antigravity" },
] as const;
export const providerLabel = (p: string) => {
  const sub = SUBSCRIPTIONS.find((s) => s.id === p);
  return sub ? `${sub.name} · suscripción` : p;
};
export const needsKey =(provider: string) => provider !== "ollama" && !SUBSCRIPTIONS.some((s) => s.id === provider);

// ts in seconds; final = team done; kind marks TechLead's questions, plan and approval requests
export type Message = { id: string; channel: string; author: string; content: string; ts: number; final?: boolean; kind?: "questions" | "plan" | "approval" };
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type FindingStatus = "DETECTED" | "CONFIRMED_BY_QA" | "PATCHED" | "VERIFIED" | "FALSE_POSITIVE" | "ACCEPTED_RISK";
export type Finding = {
  id: string;
  title: string;
  severity: Severity;
  standard: string;
  file_path: string;
  line_number: number;
  empirical_evidence: string;
  status: FindingStatus;
  fix?: string;
  endpoint?: string;
  source: string;
  history: string[];
  confidence?: "alta" | "media" | "baja";
  compliance?: string[]; // ASVS / ISO 27001 / PCI DSS controls it breaks
  accepted_reason?: string;
};
// One console entry: a test run or an AppSec scanner execution.
export type LogEntry = {
  kind: "test" | "tool"; agent: string; title: string; output: string; ok: boolean; ts: number; // ts in seconds
  id?: string; running?: boolean; ms?: number; summary?: string; args?: Record<string, string>;
};
export type InspectorTab = "findings" | "console" | "diff";
export type FindingFilter = { severity: Severity | null; status: FindingStatus | "OPEN" | null; noise?: boolean }; // noise: show low-confidence
export type AgentStatus = { status: "idle" | "thinking" | "tool"; detail: string };
export type LLM = { provider: string; model: string; api_key: string; base_url: string };

const WS_URL = import.meta.env.VITE_COVEN_WS ?? "ws://127.0.0.1:8000/ws/session";
export const API_URL = WS_URL.replace(/^ws/, "http").replace(/\/ws\/session$/, "");
const LLM_KEY = "coven.llm";
const REPO_KEY = "coven.repo";
const PREFS_KEY = "coven.prefs";
// plan: TechLead asks/plans before starting; approveFixes: pause before Fixer's patching flow; onlyChanges: git diff scope
export type Prefs = { plan: boolean; approveFixes: boolean; onlyChanges: boolean };

const load = <T,>(key: string, fallback: T): T => {
  try {
    return { ...fallback, ...JSON.parse(localStorage.getItem(key) ?? "{}") };
  } catch {
    return fallback;
  }
};

export type Usage = { calls: number; input: number; cache_write: number; cache_read: number; output: number; cost: number };

type State = {
  socket: WebSocket | null;
  running: boolean;
  projectPath: string;
  project: { name: string; stack: string[] } | null; // stack detected by the backend for projectPath
  projectError: string;
  llm: LLM;
  channels: string[];
  active: string;
  unread: Record<string, number>;
  newSince: string | null; // id of the first unread message in the channel just opened
  connected: boolean;
  messages: Message[];
  agents: Record<string, AgentStatus>;
  findings: Finding[];
  logs: LogEntry[];
  usage: Record<string, Usage>; // per agent, summed from the backend's usage events
  diff: string;
  draft: string;
  query: string;
  sidebarOpen: boolean;
  inspectorOpen: boolean;
  inspectorTab: InspectorTab;
  findingFilter: FindingFilter;
  settingsOpen: boolean;
  prefs: Prefs;
  setPrefs: (p: Partial<Prefs>) => void;
  set: (p: Partial<State>) => void;
  setLLM: (llm: LLM) => void;
  open: (channel: string) => void;
  start: (request?: string) => void;
  reset: () => void;
  send: (content: string) => void;
  fileAction: (type: "revert" | "accept", path: string) => void;
  command: (msg: Record<string, unknown>) => void; // accept_risk / reopen / publish
};

const idle = () => Object.fromEntries(Object.keys(AGENTS).map((a) => [a, { status: "idle", detail: "" }])) as State["agents"];
const sysMsg = (content: string): Message => ({ id: crypto.randomUUID(), channel: "general", author: "system", content, ts: Date.now() / 1000 });

export const useCoven = create<State>((set, get) => {
  function onEvent(e: any) {
    const s = get();
    switch (e.type) {
      case "channel_created":
        if (!s.channels.includes(e.channel)) set({ channels: [...s.channels, e.channel] });
        break;
      case "message":
        set({
          messages: [...s.messages, e],
          unread: e.channel === s.active ? s.unread : { ...s.unread, [e.channel]: (s.unread[e.channel] ?? 0) + 1 },
        });
        break;
      case "status":
        set({ agents: { ...s.agents, [e.agent]: { status: e.status, detail: e.detail } } });
        break;
      case "security_findings":
        set({ findings: e.findings });
        break;
      case "test_output":
        set({ logs: [...s.logs, { kind: "test", agent: e.agent, title: `$ ${e.command}`, output: e.output, ok: /^exit code 0\b/.test(e.output), ts: Date.now() / 1000 }] });
        break;
      case "tool_execution": {
        // "running" opens an entry, "done"/"error" fills the same one in.
        const i = s.logs.findIndex((l) => l.id === e.call_id);
        const entry: LogEntry = {
          kind: "tool", id: e.call_id, agent: e.agent, title: e.tool, args: e.args, output: e.output ?? "", summary: e.summary,
          ok: e.status !== "error", running: e.status === "running", ms: e.duration_ms, ts: i < 0 ? Date.now() / 1000 : s.logs[i].ts,
        };
        set({ logs: i < 0 ? [...s.logs, entry] : s.logs.map((l, j) => (j === i ? entry : l)) });
        break;
      }
      case "usage": {
        const u = s.usage[e.agent] ?? { calls: 0, input: 0, cache_write: 0, cache_read: 0, output: 0, cost: 0 };
        set({ usage: { ...s.usage, [e.agent]: {
          calls: u.calls + 1, input: u.input + (e.input ?? 0), cache_write: u.cache_write + (e.cache_write ?? 0),
          cache_read: u.cache_read + (e.cache_read ?? 0), output: u.output + (e.output ?? 0), cost: u.cost + (e.cost ?? 0),
        } } });
        break;
      }
      case "diff":
        set({ diff: e.diff });
        break;
      case "error":
        set({ messages: [...s.messages, sysMsg(e.message)] });
        break;
      case "done":
        set({ running: false, agents: idle() });
        break;
    }
  }

  const fresh = () => ({
    running: false, connected: false, channels: [], messages: [], findings: [], logs: [], usage: {}, diff: "",
    unread: {}, newSince: null, active: "general", agents: idle(),
  });

  return {
    socket: null,
    projectPath: load(REPO_KEY, { projectPath: "" }).projectPath,
    project: null,
    projectError: "",
    llm: { ...load(LLM_KEY, { provider: "anthropic", model: "", base_url: "", api_key: "" }), api_key: "" },
    ...fresh(),
    draft: "",
    query: "",
    sidebarOpen: true,
    inspectorOpen: true,
    inspectorTab: "findings",
    findingFilter: { severity: null, status: null },
    settingsOpen: false,
    prefs: load<Prefs>(PREFS_KEY, { plan: true, approveFixes: true, onlyChanges: false }),
    setPrefs: (p) => {
      const prefs = { ...get().prefs, ...p };
      try {
        localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
      } catch {}
      set({ prefs });
    },
    set,
    // Provider/model/base URL survive reloads; the API key deliberately stays in memory only.
    setLLM: (llm) => {
      const { api_key: _, ...rest } = llm;
      try {
        localStorage.setItem(LLM_KEY, JSON.stringify(rest));
      } catch {}
      set({ llm });
    },
    open: (channel) =>
      set((s) => {
        const inChannel = s.messages.filter((m) => m.channel === channel);
        const n = s.unread[channel] ?? 0;
        return { active: channel, unread: { ...s.unread, [channel]: 0 }, newSince: n ? inChannel[inChannel.length - n]?.id ?? null : null };
      }),
    start: (request) => {
      const { projectPath, llm, socket, prefs } = get();
      socket?.close();
      const ws = new WebSocket(WS_URL);
      set({ ...fresh(), socket: ws, running: true, draft: "" });
      ws.onopen = () => {
        set({ connected: true });
        // With a request the backend skips the initial scan and routes it directly.
        ws.send(JSON.stringify({
          type: "start", project_path: projectPath, llm, request: request?.trim() || undefined,
          plan: prefs.plan, approve_fixes: prefs.approveFixes, only_changes: prefs.onlyChanges,
        }));
      };
      ws.onmessage = (m) => onEvent(JSON.parse(m.data));
      ws.onclose = () => {
        if (get().socket !== ws) return; // replaced by a newer session
        set((s) => ({ socket: null, running: false, connected: false, agents: idle(), messages: [...s.messages, sysMsg("Conexión con el backend cerrada.")] }));
      };
      ws.onerror = () => set((s) => ({ messages: [...s.messages, sysMsg(`No se pudo conectar a ${WS_URL}. ¿Está el backend arrancado?`)] }));
    },
    reset: () => {
      const { socket } = get();
      set({ ...fresh(), socket: null, draft: "" }); // clear first so onclose ignores this socket
      socket?.close();
    },
    send: (content) => {
      const { socket, active } = get();
      if (!socket || socket.readyState !== WebSocket.OPEN || !content.trim()) return;
      socket.send(JSON.stringify({ type: "user_message", channel: active, content }));
      set({ running: true, draft: "" });
    },
    fileAction: (type, path) => get().socket?.send(JSON.stringify({ type, path })),
    command: (msg) => get().socket?.send(JSON.stringify(msg)),
  };
});

// Remember the last repo between launches.
useCoven.subscribe((s, prev) => {
  if (s.projectPath === prev.projectPath) return;
  try {
    localStorage.setItem(REPO_KEY, JSON.stringify({ projectPath: s.projectPath }));
  } catch {}
});
