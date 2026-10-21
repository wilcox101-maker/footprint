import { rebuildEdges } from "@/lib/osint/correlate";
import { hostFrom } from "@/lib/osint/guard";
import type {
  CaseFile,
  Entity,
  EntityDraft,
  Kind,
  LogEntry,
  LogLevel,
  ModuleResult,
  Monitor,
  Schedule,
  Settings,
  Severity,
  Vault,
} from "@/lib/osint/types";

const KEY = "footprint.vault.v1";
const LEGACY_KEY = "fieldnote.vault.v1";
export const VAULT_EVENT = "footprint-vault";

const LEVEL_RANK: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };
const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3 };

export function emptySettings(): Settings {
  return { hibpKey: "", vtKey: "", retentionDays: 90, staleDays: 30, logLevel: "info", showSensitive: false };
}

export function emptyVault(): Vault {
  return { cases: [], logs: [], monitors: [], settings: emptySettings() };
}

function nid(prefix: string) {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36).slice(-4)}`;
}

export function entityId(type: string, value: string) {
  return `${type}:${value.trim().toLowerCase()}`;
}

export function loadVault(): Vault {
  if (typeof window === "undefined") return emptyVault();
  try {
    let raw = localStorage.getItem(KEY);
    if (!raw) {
      const legacy = localStorage.getItem(LEGACY_KEY);
      if (legacy) {
        localStorage.setItem(KEY, legacy);
        raw = legacy;
      }
    }
    if (!raw) return emptyVault();
    const parsed = JSON.parse(raw) as Partial<Vault>;
    return {
      cases: Array.isArray(parsed.cases) ? parsed.cases : [],
      logs: Array.isArray(parsed.logs) ? parsed.logs : [],
      monitors: Array.isArray(parsed.monitors) ? parsed.monitors : [],
      settings: { ...emptySettings(), ...(parsed.settings ?? {}) },
    };
  } catch {
    return emptyVault();
  }
}

function persist(v: Vault) {
  const write = (vault: Vault) => localStorage.setItem(KEY, JSON.stringify(vault));
  try {
    write(v);
  } catch {
    for (const c of v.cases) {
      for (const s of c.scans) s.log = s.log.slice(-800);
    }
    v.logs = v.logs.slice(-200);
    write(v);
  }
  window.dispatchEvent(new Event(VAULT_EVENT));
}

export function updateVault(mut: (v: Vault) => void): Vault {
  const v = loadVault();
  mut(v);
  v.settings = { ...emptySettings(), ...v.settings };
  persist(v);
  return v;
}

function subjectType(kind: Kind): Entity["type"] {
  if (kind === "email") return "email";
  if (kind === "username") return "username";
  if (kind === "ip") return "ip";
  if (kind === "url") return "url";
  if (kind === "phone") return "phone";
  return "domain";
}

export function createCase(input: {
  target: string;
  kind: Kind;
  name?: string;
  modules: string[];
  authorized: boolean;
}): CaseFile {
  const now = new Date().toISOString();
  const subject: Entity = {
    id: entityId(subjectType(input.kind), input.kind === "url" ? hostFrom(input.kind, input.target) || input.target : input.target),
    type: subjectType(input.kind),
    value: input.kind === "url" ? input.target : input.target,
    title: "Investigation subject",
    severity: "info",
    relation: "subject",
    source: "case",
    modules: ["case"],
    firstSeen: now,
    lastSeen: now,
    historical: false,
    meta: { role: "subject" },
  };
  if (input.kind === "url") {
    const host = hostFrom("url", input.target);
    subject.meta.host = host;
  }
  const file: CaseFile = {
    id: nid("case"),
    name: (input.name || input.target).slice(0, 120),
    target: input.target,
    kind: input.kind,
    createdAt: now,
    updatedAt: now,
    notes: "",
    modules: input.modules,
    authorized: input.authorized,
    entities: [subject],
    edges: [],
    scans: [],
  };
  if (input.kind === "url") {
    const host = hostFrom("url", input.target);
    if (host && host !== input.target) {
      file.entities.push({
        id: entityId("domain", host),
        type: "domain",
        value: host,
        title: "Host of the URL",
        severity: "info",
        relation: "host",
        source: "case",
        modules: ["case"],
        firstSeen: now,
        lastSeen: now,
        historical: false,
        meta: {},
      });
    }
  }
  file.edges = rebuildEdges(file);
  updateVault((v) => {
    v.cases.unshift(file);
    pushLog(v, { level: "info", caseId: file.id, action: "case.create", message: `Opened ${file.name}` });
  });
  return file;
}

function pushLog(
  v: Vault,
  entry: { level: LogLevel; caseId?: string; action: string; message: string },
) {
  if (LEVEL_RANK[entry.level] < LEVEL_RANK[v.settings.logLevel]) return;
  const row: LogEntry = {
    id: nid("log"),
    ts: new Date().toISOString(),
    ...entry,
  };
  v.logs.unshift(row);
  if (v.logs.length > 800) v.logs.length = 800;
}

export function addLog(entry: { level: LogLevel; caseId?: string; action: string; message: string }) {
  updateVault((v) => pushLog(v, entry));
}

export function getCase(id: string): CaseFile | undefined {
  return loadVault().cases.find((c) => c.id === id);
}

export function patchCase(id: string, mut: (c: CaseFile) => void) {
  updateVault((v) => {
    const c = v.cases.find((x) => x.id === id);
    if (!c) return;
    mut(c);
    c.updatedAt = new Date().toISOString();
    c.edges = rebuildEdges(c);
  });
}

function mergeEntity(c: CaseFile, draft: EntityDraft, module: string, now: string): "added" | "refreshed" {
  const id = entityId(draft.type, draft.value);
  const existing = c.entities.find((e) => e.id === id);
  if (!existing) {
    c.entities.push({
      id,
      type: draft.type,
      value: draft.value.trim(),
      title: draft.title || draft.value,
      severity: draft.severity,
      relation: draft.relation,
      source: draft.source,
      modules: [module],
      firstSeen: now,
      lastSeen: now,
      historical: false,
      meta: { ...(draft.meta ?? {}) },
    });
    return "added";
  }
  existing.lastSeen = now;
  existing.historical = false;
  if (!existing.modules.includes(module)) existing.modules.push(module);
  if (SEV_RANK[draft.severity] > SEV_RANK[existing.severity]) existing.severity = draft.severity;
  if (draft.title && existing.title === existing.value) existing.title = draft.title;
  existing.meta = { ...existing.meta, ...(draft.meta ?? {}) };
  delete existing.meta.missingFrom;
  delete existing.meta.missingModule;
  if (draft.relation && existing.relation === "related") existing.relation = draft.relation;
  return "refreshed";
}

export function beginScan(caseId: string, modules: string[], reason: "manual" | "monitor"): string {
  const id = nid("scan");
  const now = new Date().toISOString();
  updateVault((v) => {
    const c = v.cases.find((x) => x.id === caseId);
    if (!c) return;
    c.scans.unshift({
      id,
      startedAt: now,
      finishedAt: null,
      modules,
      status: "running",
      reason,
      summary: "Running",
      added: 0,
      missing: 0,
      log: "",
    });
    if (c.scans.length > 40) {
      c.scans.length = 40;
    }
    c.updatedAt = now;
    pushLog(v, {
      level: "info",
      caseId,
      action: reason === "monitor" ? "monitor.start" : "scan.start",
      message: `Started ${modules.join(", ") || "no modules"} on ${c.target}`,
    });
  });
  return id;
}

export function applyModuleResult(caseId: string, scanId: string, result: ModuleResult) {
  const now = new Date().toISOString();
  updateVault((v) => {
    const c = v.cases.find((x) => x.id === caseId);
    const scan = c?.scans.find((s) => s.id === scanId);
    if (!c || !scan) return;
    let added = 0;
    const seen = new Set<string>();
    for (const draft of result.entities) {
      if (!draft.value?.trim()) continue;
      const id = entityId(draft.type, draft.value);
      if (seen.has(id)) continue;
      seen.add(id);
      const outcome = mergeEntity(c, draft, result.module, now);
      if (outcome === "added") added += 1;
    }
    if (result.ok && !result.truncated) {
      for (const e of c.entities) {
        if (e.meta.role === "subject") continue;
        if (!e.modules.includes(result.module)) continue;
        if (seen.has(e.id)) continue;
        if (e.meta.missingFrom === scanId) continue;
        e.meta.missingFrom = scanId;
        e.meta.missingModule = result.module;
        scan.missing += 1;
      }
    }
    scan.added += added;
    const line = result.ok
      ? `${result.module}: ${result.entities.length} rows, ${added} new`
      : `${result.module}: failed — ${result.error || "unknown"}`;
    const block = [line, ...result.log].join("\n");
    scan.log = `${scan.log}${scan.log ? "\n\n" : ""}${block}`.slice(-12_000);
    c.edges = rebuildEdges(c);
    c.updatedAt = now;
    pushLog(v, {
      level: result.ok ? "info" : "warn",
      caseId,
      action: "module.finish",
      message: line,
    });
  });
}

export function finishScan(caseId: string, scanId: string) {
  updateVault((v) => {
    const c = v.cases.find((x) => x.id === caseId);
    const scan = c?.scans.find((s) => s.id === scanId);
    if (!c || !scan) return;
    const failed = scan.log.includes(": failed");
    scan.finishedAt = new Date().toISOString();
    scan.status = !scan.log ? "error" : failed && scan.added === 0 && scan.missing === 0 ? "error" : failed ? "partial" : "ok";
    scan.summary = `+${scan.added} new, ${scan.missing} not reconfirmed`;
    c.updatedAt = scan.finishedAt;
    pushLog(v, {
      level: scan.status === "error" ? "error" : "info",
      caseId,
      action: "scan.finish",
      message: `${scan.summary} (${scan.status})`,
    });
  });
}

export function deleteCase(id: string) {
  updateVault((v) => {
    v.cases = v.cases.filter((c) => c.id !== id);
    v.monitors = v.monitors.filter((m) => m.caseId !== id);
    pushLog(v, { level: "info", action: "case.delete", message: `Deleted case ${id}` });
  });
}

export function saveNotes(id: string, notes: string) {
  patchCase(id, (c) => {
    c.notes = notes.slice(0, 4000);
  });
}

export function saveModules(id: string, modules: string[], authorized: boolean) {
  patchCase(id, (c) => {
    c.modules = modules;
    c.authorized = authorized;
  });
}

function nextFrom(schedule: Schedule, from: number) {
  const d = new Date(from);
  if (schedule === "hourly") d.setHours(d.getHours() + 1);
  else if (schedule === "daily") d.setDate(d.getDate() + 1);
  else d.setDate(d.getDate() + 7);
  return d.toISOString();
}

export function upsertMonitor(caseId: string, schedule: Schedule, modules: string[], enabled = true): Monitor {
  let saved: Monitor | undefined;
  updateVault((v) => {
    const existing = v.monitors.find((m) => m.caseId === caseId);
    const now = new Date().toISOString();
    if (existing) {
      existing.schedule = schedule;
      existing.modules = modules;
      existing.enabled = enabled;
      existing.nextRunAt = nextFrom(schedule, Date.now());
      saved = existing;
    } else {
      saved = {
        id: nid("mon"),
        caseId,
        enabled,
        schedule,
        modules,
        createdAt: now,
        lastRunAt: null,
        nextRunAt: nextFrom(schedule, Date.now()),
        lastDelta: "Not run yet",
        lastStatus: "idle",
      };
      v.monitors.unshift(saved);
    }
    pushLog(v, {
      level: "info",
      caseId,
      action: "monitor.save",
      message: `Monitor ${schedule}, ${enabled ? "on" : "off"}`,
    });
  });
  return saved!;
}

export function setMonitorEnabled(id: string, enabled: boolean) {
  updateVault((v) => {
    const m = v.monitors.find((x) => x.id === id);
    if (!m) return;
    m.enabled = enabled;
    pushLog(v, { level: "info", caseId: m.caseId, action: "monitor.toggle", message: enabled ? "Enabled" : "Paused" });
  });
}

export function removeMonitor(id: string) {
  updateVault((v) => {
    const m = v.monitors.find((x) => x.id === id);
    v.monitors = v.monitors.filter((x) => x.id !== id);
    if (m) pushLog(v, { level: "info", caseId: m.caseId, action: "monitor.delete", message: "Removed monitor" });
  });
}

export function markMonitorRun(caseId: string, delta: string, status: string) {
  updateVault((v) => {
    const m = v.monitors.find((x) => x.caseId === caseId);
    if (!m) return;
    const now = Date.now();
    m.lastRunAt = new Date(now).toISOString();
    m.nextRunAt = nextFrom(m.schedule, now);
    m.lastDelta = delta;
    m.lastStatus = status;
  });
}

export function saveSettings(patch: Partial<Settings>) {
  updateVault((v) => {
    v.settings = { ...v.settings, ...patch };
    if (v.settings.retentionDays < 7) v.settings.retentionDays = 7;
    if (v.settings.retentionDays > 3650) v.settings.retentionDays = 3650;
    if (v.settings.staleDays < 1) v.settings.staleDays = 1;
    pushLog(v, { level: "info", action: "settings.save", message: "Updated workstation settings" });
  });
}

export function tidyVault(): { logsRemoved: number; rawTrimmed: number; marked: number } {
  let logsRemoved = 0;
  let rawTrimmed = 0;
  let marked = 0;
  updateVault((v) => {
    const keepAfter = Date.now() - v.settings.retentionDays * 86_400_000;
    const staleBefore = Date.now() - v.settings.staleDays * 86_400_000;
    const before = v.logs.length;
    v.logs = v.logs.filter((l) => Date.parse(l.ts) >= keepAfter);
    logsRemoved = before - v.logs.length;
    for (const c of v.cases) {
      for (const s of c.scans) {
        if (Date.parse(s.startedAt) < keepAfter && s.log) {
          s.log = "";
          rawTrimmed += 1;
        }
      }
      const map = new Map<string, Entity>();
      for (const e of c.entities) {
        const prev = map.get(e.id);
        if (!prev) map.set(e.id, e);
        else if (Date.parse(e.lastSeen) > Date.parse(prev.lastSeen)) map.set(e.id, e);
        const row = map.get(e.id)!;
        if (row.meta.role !== "subject" && Date.parse(row.lastSeen) < staleBefore) {
          if (!row.historical) marked += 1;
          row.historical = true;
        }
      }
      c.entities = [...map.values()];
      c.edges = rebuildEdges(c);
    }
    pushLog(v, {
      level: "info",
      action: "vault.tidy",
      message: `Removed ${logsRemoved} log rows, trimmed ${rawTrimmed} raw runs, marked ${marked} stale`,
    });
  });
  return { logsRemoved, rawTrimmed, marked };
}

export function removeEntity(caseId: string, entityIdToRemove: string) {
  updateVault((v) => {
    const c = v.cases.find((item) => item.id === caseId);
    if (!c) return;
    const target = c.entities.find((entity) => entity.id === entityIdToRemove);
    if (!target || target.meta.role === "subject") return;
    c.entities = c.entities.filter((entity) => entity.id !== entityIdToRemove);
    c.edges = rebuildEdges(c);
    pushLog(v, { level: "info", caseId, action: "entity.remove", message: `Removed ${target.type} ${target.title}` });
  });
}

export function wipeFindings(caseId: string): number {
  let removed = 0;
  updateVault((v) => {
    const c = v.cases.find((item) => item.id === caseId);
    if (!c) return;
    const before = c.entities.length;
    c.entities = c.entities.filter((entity) => entity.meta.role === "subject");
    removed = before - c.entities.length;
    c.edges = rebuildEdges(c);
    for (const scan of c.scans) scan.log = "";
    pushLog(v, { level: "info", caseId, action: "case.wipe", message: `Wiped ${removed} findings` });
  });
  return removed;
}

export function purgeHistorical(caseId?: string): number {
  let removed = 0;
  updateVault((v) => {
    for (const c of v.cases) {
      if (caseId && c.id !== caseId) continue;
      const before = c.entities.length;
      c.entities = c.entities.filter((e) => e.meta.role === "subject" || !e.historical);
      removed += before - c.entities.length;
      c.edges = rebuildEdges(c);
    }
    pushLog(v, {
      level: "info",
      caseId,
      action: "vault.purge",
      message: `Removed ${removed} historical entities`,
    });
  });
  return removed;
}

export function dueMonitors(now = Date.now()): Monitor[] {
  return loadVault().monitors.filter((m) => m.enabled && Date.parse(m.nextRunAt) <= now);
}
