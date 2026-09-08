import { useSyncExternalStore } from "react";
import type { Command, CommandResult, Snapshot } from "./protocol";

export interface Preferences {
  theme: "system" | "light" | "dark";
  interval: number;
  dense: boolean;
  addresses: boolean;
}
const defaults: Preferences = {
  theme: "system",
  interval: 1000,
  dense: false,
  addresses: true,
};
function loadPreferences(): Preferences {
  try {
    const p = JSON.parse(localStorage.getItem("ferrum2.ui") ?? "{}");
    return {
      theme: ["system", "light", "dark"].includes(p.theme) ? p.theme : "system",
      interval: [1000, 2000, 5000].includes(p.interval) ? p.interval : 1000,
      dense: typeof p.dense === "boolean" ? p.dense : false,
      addresses: typeof p.addresses === "boolean" ? p.addresses : true,
    };
  } catch {
    return defaults;
  }
}
interface Sample {
  at: number;
  up: number;
  down: number;
  generation: string;
}
interface Store {
  authenticated: boolean;
  snapshot: Snapshot | null;
  received: number;
  error: string | null;
  loading: boolean;
  busy: boolean;
  hidden: boolean;
  samples: Sample[];
  preferences: Preferences;
}
let state: Store = {
  authenticated: false,
  snapshot: null,
  received: 0,
  error: null,
  loading: false,
  busy: false,
  hidden: document.hidden,
  samples: [],
  preferences: loadPreferences(),
};
let token = "";
let epoch = 0;
let timer: number | undefined;
let pending: AbortController | null = null;
const listeners = new Set<() => void>();
function update(patch: Partial<Store>) {
  state = { ...state, ...patch };
  listeners.forEach((fn) => fn());
}
export const useDashboard = () =>
  useSyncExternalStore(
    (fn) => {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    () => state,
  );
export function preferences(patch: Partial<Preferences>) {
  const p = { ...state.preferences, ...patch };
  try {
    localStorage.setItem("ferrum2.ui", JSON.stringify(p));
  } catch {
    /* Storage may be disabled; preferences still work for this tab. */
  }
  update({ preferences: p });
}
export function logout() {
  epoch++;
  token = "";
  clearTimeout(timer);
  pending?.abort();
  pending = null;
  update({
    authenticated: false,
    snapshot: null,
    received: 0,
    samples: [],
    error: null,
    loading: false,
    busy: false,
  });
}
async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const requestEpoch = epoch;
  const response = await fetch(path, {
    ...init,
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
    headers: {
      Authorization: `Bearer ${token}`,
      ...(init.body ? { "Content-Type": "application/json" } : {}),
    },
  });
  const value = await response.json();
  if (requestEpoch !== epoch) throw new Error("SESSION_CHANGED");
  if (!response.ok) {
    if (response.status === 401) {
      logout();
      update({ error: value?.error?.code ?? "UNAUTHORIZED" });
    }
    throw new Error(value?.error?.code ?? `HTTP_${response.status}`);
  }
  return value as T;
}
export async function login(value: string) {
  logout();
  token = value;
  update({ authenticated: true });
  await poll();
}
export async function poll(): Promise<void> {
  clearTimeout(timer);
  if (!token || document.hidden || pending) return;
  const current = epoch;
  const controller = new AbortController();
  pending = controller;
  const timeout = setTimeout(() => controller.abort(), 8000);
  update({ loading: true });
  try {
    const snapshot = await request<Snapshot>("/api/snapshot", {
      signal: controller.signal,
    });
    if (current !== epoch) return;
    if (snapshot.version !== 1) throw new Error("UNSUPPORTED_PROTOCOL");
    const at = Date.now();
    const samples = state.samples
      .filter(
        (s) => s.at >= at - 900000 && s.generation === snapshot.generation,
      )
      .slice(-899);
    samples.push({
      at,
      up: snapshot.traffic.upload_rate,
      down: snapshot.traffic.download_rate,
      generation: snapshot.generation,
    });
    update({ snapshot, received: at, error: null, samples });
  } catch (error) {
    if (current === epoch)
      update({
        error: error instanceof Error ? error.message : "REQUEST_FAILED",
      });
  } finally {
    clearTimeout(timeout);
    if (pending === controller) pending = null;
    if (current === epoch) {
      update({ loading: false });
      if (token && !document.hidden)
        timer = window.setTimeout(
          () => void poll(),
          state.preferences.interval,
        );
    }
  }
}
export async function command(
  command: Command,
  generation = state.snapshot?.generation,
): Promise<CommandResult> {
  if (!generation || state.busy) throw new Error("CONTROL_UNAVAILABLE");
  const current = epoch;
  update({ busy: true });
  try {
    const data = await request<{ result: CommandResult }>("/api/command", {
      method: "POST",
      body: JSON.stringify({ generation, command }),
      signal: AbortSignal.timeout(360000),
    });
    if (current !== epoch) throw new Error("SESSION_CHANGED");
    return data.result;
  } finally {
    if (current === epoch) {
      update({ busy: false });
      void poll();
    }
  }
}
export function loadConfig() {
  return request<{
    source: string;
    revision: string;
    running_revision: string | null;
  }>("/api/config", { signal: AbortSignal.timeout(10000) });
}
document.addEventListener("visibilitychange", () => {
  update({ hidden: document.hidden });
  if (document.hidden) clearTimeout(timer);
  else void poll();
});
