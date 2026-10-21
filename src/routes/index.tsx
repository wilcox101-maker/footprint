import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { formatDistanceToNow } from "date-fns";
import { useMemo, useState } from "react";

import { DayLine } from "@/components/footprint/charts";
import { Shell } from "@/components/footprint/shell";
import { Button, Panel, Stat, TextInput } from "@/components/footprint/ui";
import { PRESETS, presetFor } from "@/lib/osint/catalog";
import { assertTarget, detectKind, normalizeTarget } from "@/lib/osint/guard";
import { createCase, setMonitorEnabled } from "@/lib/osint/store";
import { dayKey, seriesByDay } from "@/lib/osint/trends";
import type { Kind } from "@/lib/osint/types";
import { useVault } from "@/lib/osint/use-vault";

export const Route = createFileRoute("/")({ component: Home });

const KINDS: { id: Kind; label: string }[] = [
  { id: "domain", label: "Domain" },
  { id: "url", label: "URL" },
  { id: "email", label: "Email" },
  { id: "username", label: "Username" },
  { id: "ip", label: "IP" },
];

function Home() {
  const { vault, ready } = useVault();
  const navigate = useNavigate();
  const [raw, setRaw] = useState("");
  const [kind, setKind] = useState<Kind>("domain");
  const [touched, setTouched] = useState(false);
  const [modules, setModules] = useState<string[]>(presetFor("domain").modules);
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");

  const weekAgo = Date.now() - 7 * 86_400_000;
  const entities = vault.cases.flatMap((c) => c.entities);
  const freshWeek = entities.filter((e) => Date.parse(e.firstSeen) >= weekAgo && e.meta.role !== "subject");
  const highs = entities.filter((e) => e.severity === "high" && !e.historical);
  const series = seriesByDay(
    entities.filter((e) => e.meta.role !== "subject"),
    Date.now() - 30 * 86_400_000,
    Date.now(),
  );

  const q = query.trim().toLowerCase();
  const hits = useMemo(() => {
    if (!q) return [];
    return vault.cases
      .flatMap((c) =>
        c.entities
          .filter((e) => e.value.toLowerCase().includes(q) || e.title.toLowerCase().includes(q) || c.name.toLowerCase().includes(q))
          .slice(0, 4)
          .map((entity) => ({ c, entity })),
      )
      .slice(0, 10);
  }, [q, vault.cases]);

  function applyKind(next: Kind) {
    setKind(next);
    setTouched(true);
    setModules(presetFor(next).modules);
    if (next !== "url" && next !== "domain") setAuthorized(false);
  }

  function onTarget(value: string) {
    setRaw(value);
    setError("");
    if (!touched) {
      const detected = detectKind(value);
      setKind(detected);
      setModules(presetFor(detected).modules);
    }
  }

  function open(run: boolean) {
    setError("");
    try {
      const target = normalizeTarget(kind, raw);
      assertTarget(kind, target);
      if (modules.includes("surface") && !authorized) {
        setError("Confirm authorization before including a surface review.");
        return;
      }
      const file = createCase({ target, kind, modules, authorized });
      if (run) sessionStorage.setItem("footprint.pendingRun", file.id);
      void navigate({ to: "/case/$caseId", params: { caseId: file.id } });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not open that scan.");
    }
  }

  return (
    <Shell>
      {!ready ? (
        <div className="grid gap-4 md:grid-cols-3">
          <div className="h-40 animate-pulse rounded-3xl bg-elevated md:col-span-2" />
          <div className="h-40 animate-pulse rounded-3xl bg-elevated" />
        </div>
      ) : (
        <div className="grid gap-5 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
          <div className="space-y-5">
            <Panel>
              <h1 className="text-2xl font-medium tracking-tight">New scan</h1>
              <p className="mt-1 max-w-xl text-sm text-muted">
                Public sources only, stored in this browser. You get a risk level, findings, and how to fix each one. Port scans and exploit checks are not run from here.
              </p>
              <div className="mt-4 flex flex-col gap-3">
                <TextInput
                  value={raw}
                  onChange={(e) => onTarget(e.target.value)}
                  placeholder="example.com, email, username, IP, or URL"
                  aria-label="Scan target"
                  onKeyDown={(e) => {
                    if (e.key === "Enter") open(true);
                  }}
                />
                <div className="flex flex-wrap gap-2">
                  {KINDS.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => applyKind(item.id)}
                      className={
                        kind === item.id
                          ? "min-h-11 rounded-lg bg-accent px-3 text-sm font-medium text-accent-fg"
                          : "min-h-11 rounded-lg border border-line px-3 text-sm text-muted hover:text-fg"
                      }
                    >
                      {item.label}
                    </button>
                  ))}
                </div>
                <div className="grid gap-2 sm:grid-cols-2">
                  {PRESETS.map((preset) => (
                    <button
                      key={preset.id}
                      type="button"
                      onClick={() => {
                        applyKind(preset.kind);
                        setModules(preset.modules);
                        setAuthorized(Boolean(preset.needsAuth) ? authorized : false);
                      }}
                      className="rounded-2xl border border-line bg-subtle px-3 py-3 text-left hover:border-line-strong"
                    >
                      <span className="block text-sm font-medium text-fg">{preset.label}</span>
                      <span className="mt-1 block text-xs leading-relaxed text-muted">{preset.blurb}</span>
                    </button>
                  ))}
                </div>
                {modules.includes("surface") ? (
                  <label className="flex items-start gap-2 text-sm text-muted">
                    <input
                      type="checkbox"
                      className="mt-1 size-4 accent-info"
                      checked={authorized}
                      onChange={(e) => setAuthorized(e.target.checked)}
                    />
                    <span>
                      I am authorized to review this host. This sends ordinary requests for the homepage, robots.txt, sitemap.xml, and security.txt. It does not scan ports or run exploit checks.
                    </span>
                  </label>
                ) : null}
                {error ? <p className="text-sm text-danger">{error}</p> : null}
                <div className="flex flex-wrap gap-2">
                  <Button type="button" onClick={() => open(true)}>
                    Start scan
                  </Button>
                  <Button type="button" variant="line" onClick={() => open(false)}>
                    Open without scanning
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    onClick={() => {
                      setRaw("example.com");
                      applyKind("domain");
                      setTouched(true);
                    }}
                  >
                    Use example.com
                  </Button>
                </div>
              </div>
            </Panel>

            <Panel>
              <div className="flex items-center justify-between gap-3">
                <h2 className="text-lg font-medium tracking-tight">Scans</h2>
                <TextInput
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search cases and entities"
                  aria-label="Search cases and entities"
                  className="max-w-xs"
                />
              </div>
              {q && hits.length ? (
                <ul className="mt-3 divide-y divide-line">
                  {hits.map(({ c, entity }) => (
                    <li key={`${c.id}-${entity.id}`}>
                      <Link
                        to="/case/$caseId"
                        params={{ caseId: c.id }}
                        className="flex min-h-11 items-center justify-between gap-3 py-2 text-sm no-underline"
                      >
                        <span className="truncate text-fg">{entity.title}</span>
                        <span className="shrink-0 font-mono text-xs text-faint">{c.name}</span>
                      </Link>
                    </li>
                  ))}
                </ul>
              ) : null}
              {q && !hits.length ? <p className="mt-3 text-sm text-muted">No matches in this browser.</p> : null}
              <ul className="mt-3 divide-y divide-line">
                {vault.cases.length ? (
                  vault.cases.map((c) => (
                    <li key={c.id}>
                      <Link to="/case/$caseId" params={{ caseId: c.id }} className="flex min-h-14 items-center justify-between gap-3 py-2 no-underline">
                        <span>
                          <span className="block text-sm font-medium text-fg">{c.name}</span>
                          <span className="block text-xs text-muted">
                            {c.kind} · {c.entities.length} entities · updated {formatDistanceToNow(new Date(c.updatedAt), { addSuffix: true })}
                          </span>
                        </span>
                        <span className="font-mono text-xs text-faint">{c.scans[0]?.summary ?? "No runs"}</span>
                      </Link>
                    </li>
                  ))
                ) : (
                  <li className="py-6 text-sm text-muted">No scans yet. Start with a domain you are allowed to research.</li>
                )}
              </ul>
            </Panel>
          </div>

          <div className="space-y-5">
            <div className="grid grid-cols-2 gap-3">
              <Stat label="Cases" value={vault.cases.length} />
              <Stat label="New this week" value={freshWeek.length} />
              <Stat label="High severity" value={highs.length} hint="InternetDB CVEs and similar" />
              <Stat label="Monitors" value={vault.monitors.filter((m) => m.enabled).length} hint="While this tab is open" />
            </div>
            <Panel>
              <h2 className="text-lg font-medium tracking-tight">Last 30 days</h2>
              <p className="mb-3 text-xs text-faint">New entities by day, {dayKey(new Date().toISOString())} included.</p>
              <DayLine data={series} />
            </Panel>
            <Panel>
              <h2 className="text-lg font-medium tracking-tight">Monitors</h2>
              <p className="mt-1 text-xs text-muted">Schedules run in this browser while Footprint is open. Nothing is sent to a cloud scheduler.</p>
              <ul className="mt-3 space-y-3">
                {vault.monitors.length ? (
                  vault.monitors.map((m) => {
                    const c = vault.cases.find((item) => item.id === m.caseId);
                    return (
                      <li key={m.id} className="rounded-2xl border border-line bg-subtle p-3">
                        <div className="flex items-start justify-between gap-2">
                          {c ? (
                            <Link to="/case/$caseId" params={{ caseId: c.id }} className="text-sm font-medium text-fg no-underline">
                              {c.name}
                            </Link>
                          ) : (
                            <span className="text-sm text-muted">Missing case</span>
                          )}
                          <button
                            type="button"
                            className="min-h-11 rounded-lg px-2 text-xs text-info"
                            onClick={() => setMonitorEnabled(m.id, !m.enabled)}
                          >
                            {m.enabled ? "Pause" : "Resume"}
                          </button>
                        </div>
                        <p className="text-xs text-muted">
                          {m.schedule} · next {formatDistanceToNow(new Date(m.nextRunAt), { addSuffix: true })}
                        </p>
                        <p className="mt-1 text-xs text-faint">{m.lastDelta}</p>
                      </li>
                    );
                  })
                ) : (
                  <li className="text-sm text-muted">No monitors. Open a case and watch it on a schedule.</li>
                )}
              </ul>
            </Panel>
          </div>
        </div>
      )}
    </Shell>
  );
}
