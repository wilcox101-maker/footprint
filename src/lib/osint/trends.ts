import type { CaseFile, Entity, Scan, Severity } from "@/lib/osint/types";

export type DateRange = {
  preset: "7" | "30" | "90" | "all" | "custom";
  from: string;
  to: string;
};

export function defaultRange(): DateRange {
  return { preset: "30", from: "", to: "" };
}

function dayStart(d: string): number {
  const [y, m, day] = d.split("-").map(Number);
  if (!y || !m || !day) return NaN;
  return new Date(y, m - 1, day).getTime();
}

export function resolveRange(r: DateRange, now = Date.now()): { from: number | null; to: number | null } {
  if (r.preset === "all") return { from: null, to: null };
  if (r.preset === "custom") {
    const from = r.from ? dayStart(r.from) : null;
    const to = r.to ? dayStart(r.to) : null;
    return {
      from: from !== null && Number.isFinite(from) ? from : null,
      to: to !== null && Number.isFinite(to) ? to + 86_400_000 - 1 : null,
    };
  }
  return { from: now - Number(r.preset) * 86_400_000, to: now };
}

export function rangeLabel(r: DateRange): string {
  if (r.preset === "all") return "All stored history";
  if (r.preset === "custom") return `${r.from || "…"} to ${r.to || "…"}`;
  return `Last ${r.preset} days`;
}

export function inWindow(iso: string, from: number | null, to: number | null): boolean {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return false;
  if (from !== null && t < from) return false;
  if (to !== null && t > to) return false;
  return true;
}

export function entityInRange(e: Entity, from: number | null, to: number | null): boolean {
  const a = Date.parse(e.firstSeen);
  const b = Date.parse(e.lastSeen);
  const start = from ?? Number.NEGATIVE_INFINITY;
  const end = to ?? Number.POSITIVE_INFINITY;
  return a <= end && b >= start;
}

export function dayKey(iso: string): string {
  const d = new Date(iso);
  const m = `${d.getMonth() + 1}`.padStart(2, "0");
  const day = `${d.getDate()}`.padStart(2, "0");
  return `${d.getFullYear()}-${m}-${day}`;
}

export function seriesByDay(entities: Entity[], from: number | null, to: number | null) {
  const map = new Map<string, number>();
  for (const e of entities) {
    if (!inWindow(e.firstSeen, from, to)) continue;
    const k = dayKey(e.firstSeen);
    map.set(k, (map.get(k) ?? 0) + 1);
  }
  return [...map.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([day, count]) => ({ day, count }));
}

export function countsByType(entities: Entity[]) {
  const map = new Map<string, number>();
  for (const e of entities) map.set(e.type, (map.get(e.type) ?? 0) + 1);
  return [...map.entries()]
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count);
}

export function countsBySeverity(entities: Entity[]) {
  const order: Severity[] = ["high", "medium", "low", "info"];
  const map = new Map<Severity, number>(order.map((s) => [s, 0]));
  for (const e of entities) map.set(e.severity, (map.get(e.severity) ?? 0) + 1);
  return order.map((severity) => ({ severity, count: map.get(severity) ?? 0 }));
}

export function trendNotes(c: CaseFile, from: number | null, to: number | null): string[] {
  const scoped = c.entities.filter((e) => entityInRange(e, from, to));
  const fresh = scoped.filter((e) => inWindow(e.firstSeen, from, to));
  const notes: string[] = [];
  notes.push(`${fresh.length} new entit${fresh.length === 1 ? "y" : "ies"} in this window.`);
  const subs = fresh.filter((e) => e.type === "subdomain").length;
  if (subs) notes.push(`${subs} subdomain${subs === 1 ? "" : "s"} first seen in this window.`);
  const highs = scoped.filter((e) => e.severity === "high").length;
  if (highs) notes.push(`${highs} high-severity item${highs === 1 ? "" : "s"} still in the window.`);
  const breaches = fresh.filter((e) => e.type === "breach").length;
  if (breaches) notes.push(`${breaches} breach title${breaches === 1 ? "" : "s"} appeared.`);
  const series = seriesByDay(c.entities, from, to);
  if (series.length >= 3) {
    const last = series[series.length - 1]?.count ?? 0;
    const prev = series.slice(0, -1).map((p) => p.count);
    const avg = prev.reduce((a, b) => a + b, 0) / prev.length;
    if (last >= 5 && avg > 0 && last > avg * 2) {
      notes.push(`Spike: ${last} new entities on ${series[series.length - 1]?.day}, more than double the earlier daily average.`);
    }
  }
  const scans = c.scans.filter((s) => s.finishedAt && inWindow(s.startedAt, from, to));
  if (scans.length) notes.push(`${scans.length} completed run${scans.length === 1 ? "" : "s"} in this window.`);
  return notes;
}

export function scanInRange(s: Scan, from: number | null, to: number | null): boolean {
  return inWindow(s.startedAt, from, to);
}
