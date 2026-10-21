import type { CaseFile, Edge, Entity } from "@/lib/osint/types";

function edgeId(from: string, relation: string, to: string) {
  return `${from}|${relation}|${to}`;
}

/** Rebuild relationship edges from the entities currently stored on a case. */
export function rebuildEdges(c: Pick<CaseFile, "entities" | "target">): Edge[] {
  const edges: Edge[] = [];
  const seen = new Set<string>();
  const byValue = new Map<string, Entity>();
  for (const e of c.entities) {
    const key = `${e.type}:${e.value.toLowerCase()}`;
    if (!byValue.has(key)) byValue.set(key, e);
    byValue.set(e.value.toLowerCase(), e);
  }

  const subject =
    c.entities.find((e) => e.meta.role === "subject") ??
    c.entities.find((e) => e.value.toLowerCase() === c.target.toLowerCase());

  function add(from: Entity | undefined, to: Entity | undefined, relation: string) {
    if (!from || !to || from.id === to.id) return;
    const id = edgeId(from.id, relation, to.id);
    if (seen.has(id)) return;
    seen.add(id);
    edges.push({ id, from: from.id, to: to.id, relation });
  }

  for (const e of c.entities) {
    if (subject && e.id !== subject.id) add(subject, e, e.relation || "related");

    if (e.type === "email" && e.value.includes("@")) {
      const dom = e.value.split("@")[1]?.toLowerCase();
      const host = c.entities.find(
        (x) => (x.type === "domain" || x.type === "subdomain") && x.value.toLowerCase() === dom,
      );
      add(e, host, "uses-domain");
    }

    const link = e.meta.linkTo?.toLowerCase();
    if (link && e.meta.linkRel) {
      const other =
        c.entities.find((x) => x.value.toLowerCase() === link) ??
        c.entities.find((x) => x.id.toLowerCase().endsWith(`:${link}`));
      add(e, other, e.meta.linkRel);
    }

    const host = e.meta.host?.toLowerCase();
    if (host) {
      const node = c.entities.find(
        (x) => (x.type === "domain" || x.type === "subdomain" || x.type === "ip") && x.value.toLowerCase() === host,
      );
      add(e, node, e.type === "profile" ? "profile-on" : "hosted-on");
    }
  }

  return edges;
}
