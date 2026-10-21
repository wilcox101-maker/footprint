import { useEffect, useMemo, useRef, useState } from "react";

import { TextInput } from "@/components/footprint/ui";
import type { Edge, Entity, EntityType } from "@/lib/osint/types";

type PNode = {
  id: string;
  x: number;
  y: number;
  label: string;
  type: EntityType;
  severity: Entity["severity"];
  historical: boolean;
  subject: boolean;
};

const TYPE_COLOR: Record<string, string> = {
  domain: "--color-fg",
  subdomain: "--color-info",
  ip: "--color-ok",
  email: "--color-warn",
  username: "--color-fg",
  url: "--color-info",
  profile: "--color-info",
  breach: "--color-danger",
  tech: "--color-muted",
  finding: "--color-warn",
  asn: "--color-ok",
  port: "--color-muted",
  cve: "--color-danger",
};

export function GraphPanel({ entities, edges }: { entities: Entity[]; edges: Edge[] }) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const nodesRef = useRef<PNode[]>([]);
  const [query, setQuery] = useState("");
  const [type, setType] = useState("all");
  const [hideHistorical, setHideHistorical] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const queryRef = useRef(query);
  const selectedRef = useRef(selected);
  const hoverRef = useRef(hover);
  queryRef.current = query;
  selectedRef.current = selected;
  hoverRef.current = hover;

  const visible = useMemo(() => {
    return entities.filter((e) => {
      if (hideHistorical && e.historical && e.meta.role !== "subject") return false;
      if (type !== "all" && e.type !== type && e.meta.role !== "subject") return false;
      return true;
    });
  }, [entities, hideHistorical, type]);

  const capped = visible.slice(0, 120);
  const idSet = useMemo(() => new Set(capped.map((e) => e.id)), [capped]);
  const visEdges = edges.filter((e) => idSet.has(e.from) && idSet.has(e.to));
  const signature = `${capped.map((e) => `${e.id}:${e.type}`).join(",")}|${visEdges.length}`;

  useEffect(() => {
    const canvas = canvasRef.current;
    const wrap = wrapRef.current;
    if (!canvas || !wrap) return;
    const width = wrap.clientWidth;
    const height = width < 640 ? 340 : 460;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const styles = getComputedStyle(document.documentElement);
    const color = (token: string, fallback: string) => styles.getPropertyValue(token).trim() || fallback;
    const ink = color("--color-fg", "#e7ecef");
    const muted = color("--color-muted", "#9aa6b2");
    const line = color("--color-line-strong", "#3d4854");

    const cx = width / 2;
    const cy = height / 2;
    const nodes: PNode[] = capped.map((e) => ({
      id: e.id,
      x: cx,
      y: cy,
      label: (e.title || e.value).slice(0, 48),
      type: e.type,
      severity: e.severity,
      historical: e.historical,
      subject: e.meta.role === "subject",
    }));
    const subject = nodes.find((n) => n.subject) ?? nodes[0];
    const others = nodes.filter((n) => n !== subject);
    const byType = new Map<string, PNode[]>();
    for (const node of others) {
      const list = byType.get(node.type) ?? [];
      list.push(node);
      byType.set(node.type, list);
    }
    const types = [...byType.keys()];
    const rx = Math.max(90, Math.min(width, height) * 0.34);
    const ry = rx * (height / Math.max(width, 1) > 0.8 ? 0.72 : 0.86);
    let cursor = 0;
    const total = Math.max(others.length, 1);
    for (const key of types) {
      const list = byType.get(key) ?? [];
      list.forEach((node, index) => {
        const slot = cursor + index;
        const angle = (slot / total) * Math.PI * 2 - Math.PI / 2;
        const band = list.length > 18 && index % 2 === 1 ? 0.78 : 1;
        node.x = cx + Math.cos(angle) * rx * band;
        node.y = cy + Math.sin(angle) * ry * band;
      });
      cursor += list.length;
    }
    if (subject) {
      subject.x = cx;
      subject.y = cy;
    }
    nodesRef.current = nodes;
    const index = new Map(nodes.map((n) => [n.id, n]));

    const draw = () => {
      ctx.clearRect(0, 0, width, height);
      const focus = hoverRef.current || selectedRef.current;
      for (const edge of visEdges) {
        const a = index.get(edge.from);
        const b = index.get(edge.to);
        if (!a || !b) continue;
        const hot = focus && (edge.from === focus || edge.to === focus);
        ctx.strokeStyle = hot ? color("--color-info", ink) : line;
        ctx.globalAlpha = focus && !hot ? 0.15 : 0.85;
        ctx.lineWidth = hot ? 1.5 : 1;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();
      }
      ctx.globalAlpha = 1;
      const q = queryRef.current.trim().toLowerCase();
      for (const node of nodes) {
        const dim = q && !`${node.label} ${node.id}`.toLowerCase().includes(q);
        ctx.globalAlpha = dim ? 0.18 : node.historical ? 0.45 : 1;
        ctx.beginPath();
        ctx.fillStyle = color(TYPE_COLOR[node.type] ?? "--color-fg", ink);
        const active = node.id === selectedRef.current || node.id === hoverRef.current;
        const r = node.subject ? 9 : active ? 7 : node.severity === "high" ? 6 : 4.5;
        ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
        ctx.fill();
        if (active || node.subject) {
          ctx.lineWidth = 1.5;
          ctx.strokeStyle = ink;
          ctx.stroke();
        }
        if (active || nodes.length < 18) {
          ctx.font = "12px IBM Plex Sans, sans-serif";
          ctx.fillStyle = ink;
          ctx.fillText(node.label, node.x + 10, node.y + 4);
        }
      }
      ctx.globalAlpha = 1;
    };
    draw();

    const point = (event: PointerEvent) => {
      const rect = canvas.getBoundingClientRect();
      return { x: event.clientX - rect.left, y: event.clientY - rect.top };
    };
    const hit = (x: number, y: number) => {
      for (let i = nodes.length - 1; i >= 0; i -= 1) {
        const n = nodes[i]!;
        if (Math.hypot(n.x - x, n.y - y) <= 12) return n;
      }
      return null;
    };
    const move = (event: PointerEvent) => {
      const p = point(event);
      const node = hit(p.x, p.y);
      const id = node?.id ?? null;
      if (id !== hoverRef.current) {
        hoverRef.current = id;
        setHover(id);
        draw();
      }
    };
    const down = (event: PointerEvent) => {
      const p = point(event);
      const node = hit(p.x, p.y);
      selectedRef.current = node?.id ?? null;
      setSelected(node?.id ?? null);
      draw();
    };
    const leave = () => {
      hoverRef.current = null;
      setHover(null);
      draw();
    };
    canvas.addEventListener("pointermove", move);
    canvas.addEventListener("pointerdown", down);
    canvas.addEventListener("pointerleave", leave);
    return () => {
      canvas.removeEventListener("pointermove", move);
      canvas.removeEventListener("pointerdown", down);
      canvas.removeEventListener("pointerleave", leave);
    };
  }, [signature]);

  useEffect(() => {
    const canvas = canvasRef.current;
    canvas?.dispatchEvent(new Event("pointerleave"));
  }, [query, selected]);

  const types = [...new Set(entities.map((e) => e.type))];
  const current = entities.find((e) => e.id === (hover || selected));

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center">
        <TextInput
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Highlight in the graph"
          aria-label="Highlight in the graph"
          className="sm:max-w-xs"
        />
        <label className="flex min-h-11 items-center gap-2 text-sm text-muted">
          <span className="sr-only">Entity type</span>
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="min-h-11 rounded-lg border border-line bg-subtle px-3 text-sm text-fg"
          >
            <option value="all">All types</option>
            {types.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <label className="flex min-h-11 items-center gap-2 text-sm text-muted">
          <input type="checkbox" checked={hideHistorical} onChange={(e) => setHideHistorical(e.target.checked)} className="size-4 accent-info" />
          Hide historical
        </label>
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted">
        {types.map((t) => (
          <span key={t} className="inline-flex items-center gap-1">
            <span className="inline-block size-2 rounded-full" style={{ background: `var(${TYPE_COLOR[t] ?? "--color-fg"})` }} />
            {t}
          </span>
        ))}
      </div>
      <div ref={wrapRef} className="overflow-hidden rounded-2xl border border-line bg-bg">
        <canvas ref={canvasRef} className="block w-full touch-none" role="img" aria-label="Entity relationship graph" />
      </div>
      {visible.length > capped.length ? (
        <p className="text-xs text-faint">
          Showing {capped.length} of {visible.length} nodes. Filter by type to see the rest.
        </p>
      ) : (
        <p className="text-xs text-faint">Subject sits in the center. Hover or click a node to read it.</p>
      )}
      {current ? (
        <div className="rounded-2xl border border-line bg-subtle p-3 text-sm">
          <p className="font-medium text-fg">{current.title}</p>
          <p className="mt-1 break-all font-mono text-xs text-muted">{current.value}</p>
          <p className="mt-1 text-xs text-faint">
            {current.type} · {current.severity} · {current.source} · {current.relation}
          </p>
        </div>
      ) : null}
      <ul className="sr-only">
        {visEdges.slice(0, 80).map((e) => (
          <li key={e.id}>
            {e.from} {e.relation} {e.to}
          </li>
        ))}
      </ul>
    </div>
  );
}
