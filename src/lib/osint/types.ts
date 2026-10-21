export const KINDS = ["domain", "email", "username", "ip", "url", "phone"] as const;
export type Kind = (typeof KINDS)[number];

export const SEVERITIES = ["info", "low", "medium", "high"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const ENTITY_TYPES = [
  "domain",
  "subdomain",
  "ip",
  "email",
  "username",
  "url",
  "profile",
  "breach",
  "tech",
  "finding",
  "asn",
  "port",
  "cve",
  "phone",
] as const;
export type EntityType = (typeof ENTITY_TYPES)[number];

export type Entity = {
  id: string;
  type: EntityType;
  value: string;
  title: string;
  severity: Severity;
  relation: string;
  source: string;
  modules: string[];
  firstSeen: string;
  lastSeen: string;
  historical: boolean;
  meta: Record<string, string>;
};

export type Edge = {
  id: string;
  from: string;
  to: string;
  relation: string;
};

export type Scan = {
  id: string;
  startedAt: string;
  finishedAt: string | null;
  modules: string[];
  status: "running" | "ok" | "partial" | "error";
  reason: "manual" | "monitor";
  summary: string;
  added: number;
  missing: number;
  log: string;
};

export type RemovalAttempt = {
  at: string;
  broker: string;
  channel: "mail" | "form";
  listingUrl: string;
};

export type CaseFile = {
  id: string;
  name: string;
  target: string;
  kind: Kind;
  createdAt: string;
  updatedAt: string;
  notes: string;
  modules: string[];
  authorized: boolean;
  entities: Entity[];
  edges: Edge[];
  scans: Scan[];
  /** Requests the operator opened. Not a receipt from the broker. */
  removals?: RemovalAttempt[];
};

export type LogLevel = "debug" | "info" | "warn" | "error";

export type LogEntry = {
  id: string;
  ts: string;
  level: LogLevel;
  caseId?: string;
  action: string;
  message: string;
};

export type Schedule = "hourly" | "daily" | "weekly";

export type Monitor = {
  id: string;
  caseId: string;
  enabled: boolean;
  schedule: Schedule;
  modules: string[];
  createdAt: string;
  lastRunAt: string | null;
  nextRunAt: string;
  lastDelta: string;
  lastStatus: string;
};

export type Settings = {
  hibpKey: string;
  vtKey: string;
  retentionDays: number;
  staleDays: number;
  logLevel: LogLevel;
  /** When false, published photos and contact fields stay masked in the UI. */
  showSensitive: boolean;
};

export type Vault = {
  cases: CaseFile[];
  logs: LogEntry[];
  monitors: Monitor[];
  settings: Settings;
};

export type EntityDraft = {
  type: EntityType;
  value: string;
  severity: Severity;
  relation: string;
  source: string;
  title?: string;
  meta?: Record<string, string>;
};

export type ModuleResult = {
  module: string;
  ok: boolean;
  truncated: boolean;
  error?: string;
  durationMs: number;
  entities: EntityDraft[];
  log: string[];
};

export type RunInput = {
  target: string;
  kind: Kind;
  modules: string[];
  authorized: boolean;
  hibpKey?: string;
  vtKey?: string;
};

export const LEGAL =
  "This tool performs open-source intelligence collection and optional active scanning. You are solely responsible for ensuring you have authorization to scan any target. Unauthorized scanning of systems you do not own or have permission to test is illegal in most jurisdictions. Use only on your own assets or with explicit written permission. The developers and this software assume no liability.";
