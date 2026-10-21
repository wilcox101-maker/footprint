import { displayEntity, maskText } from "@/lib/osint/sensitive";
import { LEGAL } from "@/lib/osint/types";
import type { CaseFile, Entity } from "@/lib/osint/types";
import { rangeLabel, type DateRange } from "@/lib/osint/trends";

function esc(s: string) {
  return s
    .replaceAll("&", "&" + "amp;")
    .replaceAll("<", "&" + "lt;")
    .replaceAll(">", "&" + "gt;")
    .replaceAll('"', "&" + "quot;");
}

const DROPPED_META = new Set(["photo", "phone", "address", "classes", "location", "company", "twitter"]);

/** Exports follow the public-details switch so a download does not unmask the screen. */
export function presentEntities(entities: Entity[], showDetails: boolean): Entity[] {
  if (showDetails) return entities;
  return entities.map((entity) => {
    const shown = displayEntity(entity, false);
    const meta: Record<string, string> = {};
    for (const [key, value] of Object.entries(entity.meta)) {
      if (DROPPED_META.has(key)) continue;
      meta[key] = maskText(value);
    }
    return { ...entity, title: shown.title, value: shown.value, meta };
  });
}

export function reportMarkdown(c: CaseFile, entities: Entity[], notes: string[], range: DateRange, showDetails = false) {
  const rows = presentEntities(entities, showDetails);
  const lines = [
    `# Footprint report — ${c.name}`,
    "",
    `Target: \`${c.target}\` (${c.kind})`,
    `Window: ${rangeLabel(range)}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    `> ${LEGAL}`,
    "",
    "## Trend notes",
    "",
    ...notes.map((n) => `- ${n}`),
    "",
    "## Entities",
    "",
    "| Type | Value | Severity | Source | Last seen |",
    "| --- | --- | --- | --- | --- |",
    ...rows.slice(0, 500).map((e) => `| ${e.type} | ${e.value.replace(/\|/g, "/")} | ${e.severity} | ${e.source} | ${e.lastSeen} |`),
    "",
    c.notes ? `## Notes\n\n${c.notes}\n` : "",
  ];
  return lines.filter((l) => l !== undefined).join("\n");
}

export function reportCsv(entities: Entity[], showDetails = false) {
  const rows = presentEntities(entities, showDetails);
  const head = ["type", "value", "title", "severity", "source", "relation", "firstSeen", "lastSeen", "historical"];
  const body = rows.map((e) =>
    [e.type, e.value, e.title, e.severity, e.source, e.relation, e.firstSeen, e.lastSeen, String(e.historical)]
      .map((cell) => `"${cell.replace(/"/g, '""')}"`)
      .join(","),
  );
  return [head.join(","), ...body].join("\n");
}

export function reportJson(c: CaseFile, entities: Entity[], notes: string[], range: DateRange, showDetails = false) {
  const rows = presentEntities(entities, showDetails);
  return JSON.stringify(
    {
      disclaimer: LEGAL,
      generatedAt: new Date().toISOString(),
      range: rangeLabel(range),
      case: { id: c.id, name: c.name, target: c.target, kind: c.kind, notes: c.notes },
      notes,
      entities: rows,
      edges: c.edges.filter((e) => rows.some((n) => n.id === e.from) && rows.some((n) => n.id === e.to)),
    },
    null,
    2,
  );
}

export function reportHtml(c: CaseFile, entities: Entity[], notes: string[], range: DateRange, showDetails = false) {
  const rows = presentEntities(entities, showDetails)
    .slice(0, 500)
    .map(
      (e) =>
        `<tr><td>${esc(e.type)}</td><td>${esc(e.value)}</td><td>${esc(e.severity)}</td><td>${esc(e.source)}</td><td>${esc(e.lastSeen)}</td></tr>`,
    )
    .join("");
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>${esc(c.name)} — Footprint</title>
<style>
  body{font-family:Georgia,serif;background:#f4f1ea;color:#1c1915;margin:2rem auto;max-width:52rem;line-height:1.45}
  h1{font-weight:500;letter-spacing:-0.03em} table{border-collapse:collapse;width:100%;font-family:ui-monospace,monospace;font-size:12px}
  td,th{border-bottom:1px solid #ddd4c6;text-align:left;padding:6px 8px;vertical-align:top} th{font-family:Georgia,serif}
  .note{color:#5c564c} blockquote{border-left:3px solid #1c1915;padding-left:12px;color:#3f3a33}
</style></head><body>
<h1>${esc(c.name)}</h1>
<p class="note">${esc(c.target)} · ${esc(c.kind)} · ${esc(rangeLabel(range))}</p>
<blockquote>${esc(LEGAL)}</blockquote>
<h2>Trend notes</h2>
<ul>${notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>
<h2>Entities</h2>
<table><thead><tr><th>Type</th><th>Value</th><th>Severity</th><th>Source</th><th>Last seen</th></tr></thead>
<tbody>${rows}</tbody></table>
</body></html>`;
}
