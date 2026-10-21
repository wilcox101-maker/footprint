import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { format } from "date-fns";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { CountBars, DayLine } from "@/components/footprint/charts";
import { ExposureBoard } from "@/components/footprint/exposure-board";
import { GraphPanel } from "@/components/footprint/graph-panel";
import { Shell } from "@/components/footprint/shell";
import { Button, Panel, SelectInput, TextArea, TextInput } from "@/components/footprint/ui";
import { modulesFor, type ModuleDef } from "@/lib/osint/catalog";
import { byRisk, howToFix, overallRisk, riskCounts, riskOf, whatItMeans, type RiskLevel } from "@/lib/osint/findings";
import { exposureRows } from "@/lib/osint/exposure";
import { reportCsv, reportHtml, reportJson, reportMarkdown } from "@/lib/osint/report";
import { runBusy, runCase } from "@/lib/osint/run-client";
import { displayEntity, listingMatches, maskText, removalLetter, removalMailto, TAKEDOWN_LINKS, TAKEDOWN_METHOD, type RemovalLink } from "@/lib/osint/sensitive";
import {
  deleteCase,
  purgeHistorical,
  removeEntity,
  removeMonitor,
  recordRemoval,
  saveModules,
  saveNotes,
  upsertMonitor,
} from "@/lib/osint/store";
import {
  countsByType,
  defaultRange,
  entityInRange,
  rangeLabel,
  resolveRange,
  scanInRange,
  seriesByDay,
  trendNotes,
  type DateRange,
} from "@/lib/osint/trends";
import type { Entity, Schedule } from "@/lib/osint/types";
import { useVault } from "@/lib/osint/use-vault";

export const Route = createFileRoute("/case/$caseId")({ component: CasePage });

function groupedModules(catalog: ModuleDef[]): [string, ModuleDef[]][] {
  const groups: [string, ModuleDef[]][] = [];
  for (const mod of catalog) {
    const found = groups.find((row) => row[0] === mod.group);
    if (found) found[1].push(mod);
    else groups.push([mod.group, [mod]]);
  }
  return groups;
}

const TABS = ["Overview", "Findings", "Assets", "Leaks", "Footprint", "Graph", "Report"] as const;
type Tab = (typeof TABS)[number];

const started = new Set<string>();

function download(name: string, body: string, type: string) {
  const blob = new Blob([body], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function CasePage() {
  const { caseId } = Route.useParams();
  const navigate = useNavigate();
  const { vault, ready } = useVault();
  const file = vault.cases.find((c) => c.id === caseId);
  const monitor = file ? vault.monitors.find((m) => m.caseId === file.id) : undefined;
  const [tab, setTab] = useState<Tab>("Overview");
  const [lens, setLens] = useState<"simple" | "technical">("simple");
  const [riskFilter, setRiskFilter] = useState<RiskLevel | "All">("All");
  const [range, setRange] = useState<DateRange>(defaultRange);
  const [status, setStatus] = useState("");
  const [running, setRunning] = useState(false);
  const [notes, setNotes] = useState("");
  const [schedule, setSchedule] = useState<Schedule>("daily");
  const [removeName, setRemoveName] = useState("");
  const [removeEmail, setRemoveEmail] = useState("");
  const [listingUrl, setListingUrl] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    if (monitor?.schedule) setSchedule(monitor.schedule);
  }, [monitor?.schedule]);

  useEffect(() => {
    if (file) setNotes(file.notes);
  }, [file?.id, file?.notes]);

  useEffect(() => {
    if (lens === "simple" && tab === "Graph") setTab("Overview");
  }, [lens, tab]);

  useEffect(() => {
    if (!ready || !file) return;
    const pending = sessionStorage.getItem("footprint.pendingRun") ?? sessionStorage.getItem("fieldnote.pendingRun");
    if (pending !== file.id || started.has(file.id)) return;
    started.add(file.id);
    sessionStorage.removeItem("footprint.pendingRun");
    sessionStorage.removeItem("fieldnote.pendingRun");
    void start();
    // start closes over the latest file via getCase inside runCase
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, file?.id]);

  const bounds = resolveRange(range);
  const entities = useMemo(
    () => (file ? file.entities.filter((e) => entityInRange(e, bounds.from, bounds.to)) : []),
    [file, bounds.from, bounds.to],
  );
  const notesTrend = file ? trendNotes(file, bounds.from, bounds.to) : [];

  async function start() {
    if (!file || running || runBusy()) return;
    setRunning(true);
    setStatus("Starting");
    const result = await runCase(file.id, "manual", setStatus);
    setRunning(false);
    setStatus("");
    if (result.highs) toast.warning(`${result.highs} high-severity item${result.highs === 1 ? "" : "s"} in this run`);
    else toast(result.message);
  }

  if (!ready) {
    return (
      <Shell>
        <div className="h-48 animate-pulse rounded-3xl bg-elevated" />
      </Shell>
    );
  }

  if (!file) {
    return (
      <Shell>
        <Panel>
          <h1 className="text-xl font-medium">Scan not in this browser</h1>
          <p className="mt-2 text-sm text-muted">Scans stay in local storage on this device.</p>
          <Link to="/" className="mt-4 inline-flex min-h-11 items-center text-sm text-info">
            Back to scans
          </Link>
        </Panel>
      </Shell>
    );
  }

  const catalog = modulesFor(file.kind);
  const scans = file.scans.filter((s) => scanInRange(s, bounds.from, bounds.to));
  const logs = vault.logs.filter((l) => l.caseId === file.id && (!bounds.from || Date.parse(l.ts) >= bounds.from) && (!bounds.to || Date.parse(l.ts) <= bounds.to));
  const showDetails = Boolean(vault.settings.showSensitive);
  const ranked = byRisk(entities);
  const counts = riskCounts(entities);
  const risk = overallRisk(ranked);
  const priorities = ranked.filter((entity) => riskOf(entity) !== "Info").slice(0, 5);
  const lastScan = file.scans[0];
  const scanStatus = running ? "Running" : lastScan ? (lastScan.status === "ok" ? "Finished" : lastScan.status === "running" ? "Running" : "Finished with gaps") : "Not run";
  const stamp = file.target.replace(/[^a-z0-9.-]+/gi, "_").slice(0, 40);

  function setModule(id: string, on: boolean) {
    if (!file) return;
    const next = on ? [...new Set([...file.modules, id])] : file.modules.filter((m) => m !== id);
    const authorized = next.includes("surface") ? file.authorized : false;
    saveModules(file.id, next, authorized);
  }

  function requestRemoval(link: RemovalLink, channel: "mail" | "form") {
    if (!file) return;
    const name = removeName.trim();
    const email = removeEmail.trim();
    const url = listingUrl.trim();
    if (channel === "form") {
      if (url) recordRemoval(file.id, { broker: link.title, channel: "form", listingUrl: url });
      window.open(link.href, "_blank", "noopener,noreferrer");
      toast(url ? "Official form opened. Finish it there, then confirm the broker’s email." : "Official form opened.");
      return;
    }
    if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !url) {
      toast("Enter your name, an email you can confirm, and the listing URL.");
      return;
    }
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      toast("Paste a full listing URL, including https://.");
      return;
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      toast("The listing URL has to be a web address.");
      return;
    }
    if (channel === "mail") {
      if (!link.mail) {
        toast("This broker has no published mailbox. Open the official form.");
        return;
      }
      if (!listingMatches(link, url)) {
        toast(`That listing is not on ${link.hosts?.join(" or ")}.`);
        return;
      }
      const href = removalMailto(link, { name, email, listingUrl: url, target: file.target, kind: file.kind });
      if (!href) return;
      recordRemoval(file.id, { broker: link.title, channel: "mail", listingUrl: url });
      window.location.href = href;
      toast("Opened in your mail app. You still have to send it.");
      return;
    }
    recordRemoval(file.id, { broker: link.title, channel: "form", listingUrl: url });
    window.open(link.href, "_blank", "noopener,noreferrer");
    toast("Official form opened. Finish it there, then confirm the broker’s email.");
  }

  return (
    <Shell>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className={scanStatus === "Finished" ? "rounded-md bg-ok/15 px-2 py-0.5 text-xs font-medium text-ok" : scanStatus === "Running" ? "rounded-md bg-warn/15 px-2 py-0.5 text-xs font-medium text-warn" : "rounded-md bg-subtle px-2 py-0.5 text-xs font-medium text-muted"}>
              {scanStatus}
            </span>
            <span className="font-mono text-xs uppercase tracking-wide text-faint">{file.kind} scan</span>
          </div>
          <h1 className="mt-1 break-all text-2xl font-medium tracking-tight">{file.name}</h1>
          <p className="text-sm text-muted">
            {lastScan
              ? `Started ${format(new Date(lastScan.startedAt), "d MMM yyyy HH:mm")}${lastScan.finishedAt ? ` · finished ${format(new Date(lastScan.finishedAt), "HH:mm")}` : ""} · ${lastScan.modules.length} checks`
              : `Opened ${format(new Date(file.createdAt), "d MMM yyyy")} · no scan yet`}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <div className="flex rounded-lg border border-line p-0.5" role="group" aria-label="How much detail">
            <button type="button" onClick={() => setLens("simple")} className={lens === "simple" ? "min-h-11 rounded-md bg-accent px-3 text-sm font-medium text-accent-fg" : "min-h-11 rounded-md px-3 text-sm text-muted"}>
              Simple
            </button>
            <button type="button" onClick={() => setLens("technical")} className={lens === "technical" ? "min-h-11 rounded-md bg-accent px-3 text-sm font-medium text-accent-fg" : "min-h-11 rounded-md px-3 text-sm text-muted"}>
              Technical
            </button>
          </div>
          <Button type="button" onClick={() => void start()} disabled={running}>
            {running ? "Running" : "Start scan"}
          </Button>
          <Button
            type="button"
            variant="danger"
            onClick={() => {
              if (!confirmDelete) {
                setConfirmDelete(true);
                return;
              }
              deleteCase(file.id);
              void navigate({ to: "/" });
            }}
          >
            {confirmDelete ? "Confirm delete" : "Delete scan"}
          </Button>
        </div>
      </div>

      <Panel className="mb-4">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-sm font-semibold text-fg">Scan progress</p>
            <p className={`text-xs ${scanStatus === "Finished" ? "text-ok" : scanStatus === "Running" ? "text-warn" : "text-muted"}`}>
              {scanStatus === "Finished" ? "Completed" : scanStatus === "Running" ? "Running" : scanStatus}
            </p>
          </div>
          <div className="flex min-w-[12rem] flex-1 items-center gap-3 sm:max-w-md sm:flex-none">
            <div className="h-3 flex-1 overflow-hidden rounded-full bg-subtle">
              <div
                className={`h-full rounded-full ${scanStatus === "Running" ? "w-2/3 bg-warn" : scanStatus === "Not run" ? "w-0" : "w-full bg-ok"}`}
              />
            </div>
            <span className="font-mono text-xs text-fg">{scanStatus === "Running" ? "…" : scanStatus === "Not run" ? "0%" : "100%"}</span>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
          {(
            [
              ["Critical", "Critical", "border-l-[#e85d4c]"],
              ["High", "High Risk", "border-l-[#f5a623]"],
              ["Medium", "Medium Risk", "border-l-[#e6c15a]"],
              ["Low", "Low Risk", "border-l-[#3dbe7a]"],
              ["Info", "Informational", "border-l-[#8aa0b4]"],
            ] as const
          ).map(([level, label, rail]) => (
            <button
              key={level}
              type="button"
              onClick={() => {
                setRiskFilter(level);
                setTab("Findings");
              }}
              className={`min-h-24 rounded-2xl border border-line border-l-4 bg-[#152033] px-4 py-3 text-left ${rail}`}
            >
              <span className="block font-mono text-2xl tabular-nums text-fg">{counts[level]}</span>
              <span className="mt-1 block text-sm text-muted">{label}</span>
            </button>
          ))}
        </div>
        <div className="mt-4 grid gap-4 border-t border-line pt-4 lg:grid-cols-[12rem_minmax(0,1fr)]">
          <div>
            <p className="text-xs uppercase tracking-wide text-faint">Overall risk</p>
            <p className={`mt-2 inline-flex rounded-lg px-3 py-2 text-lg font-medium ${riskTone(risk)}`}>{risk}</p>
            <p className="mt-2 text-xs leading-relaxed text-muted">{riskBlurb(risk)}</p>
          </div>
          <div className="text-sm">
            <p className="text-xs uppercase tracking-wide text-faint">Scan information</p>
            <dl className="mt-2 space-y-1 text-muted sm:max-w-sm">
              <div className="flex justify-between gap-3"><dt>Status</dt><dd className="text-fg">{scanStatus}</dd></div>
              <div className="flex justify-between gap-3"><dt>Checks selected</dt><dd className="text-fg">{file.modules.length}</dd></div>
              <div className="flex justify-between gap-3"><dt>Findings in window</dt><dd className="text-fg">{ranked.length}</dd></div>
              <div className="flex justify-between gap-3"><dt>Not reconfirmed</dt><dd className="text-fg">{lastScan?.missing ?? 0}</dd></div>
            </dl>
            {running ? <p className="mt-2 text-xs text-warn">{status || "Working"}</p> : null}
          </div>
        </div>
      </Panel>

      <div className="mb-4">
        <ExposureBoard
          rows={exposureRows(file, entities, showDetails)}
          checksReady={catalog.length}
          checksFinished={lastScan && lastScan.status !== "running" ? lastScan.modules.length : null}
          brokerCount={TAKEDOWN_LINKS.filter((link) => link.group === "Data brokers").length}
          onOpenBrokers={() => setTab("Footprint")}
        />
      </div>

      <details className="mb-4 rounded-3xl border border-line bg-elevated px-4 py-3 sm:px-5">
        <summary className="min-h-11 cursor-pointer text-sm font-medium text-fg">Checks in this scan</summary>
        <p className="mt-1 text-xs text-muted">Public sources only. Surface review is the one check that touches the site, and only after you confirm you are allowed to.</p>
        <div className="mt-3 space-y-4">
          {groupedModules(catalog).map(([group, mods]) => (
            <div key={group}>
              <h3 className="mb-2 text-xs font-medium tracking-wide text-faint">{group}</h3>
              <ul className="grid gap-2 sm:grid-cols-2">
                {mods.map((mod) => {
                  const on = file.modules.includes(mod.id);
                  return (
                    <li key={mod.id}>
                      <label className="flex min-h-11 items-start gap-2 rounded-2xl border border-line bg-subtle px-3 py-2">
                        <input
                          type="checkbox"
                          className="mt-1 size-4 accent-info"
                          checked={on}
                          onChange={(e) => setModule(mod.id, e.target.checked)}
                        />
                        <span>
                          <span className="block text-sm text-fg">
                            {mod.label}
                            {!mod.passive ? <span className="ml-2 text-xs text-warn">Authorized only</span> : null}
                          </span>
                          <span className="block text-xs text-muted">{mod.detail}</span>
                        </span>
                      </label>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </div>
        {file.modules.includes("surface") ? (
          <label className="mt-3 flex items-start gap-2 text-sm text-muted">
            <input
              type="checkbox"
              className="mt-1 size-4 accent-info"
              checked={file.authorized}
              onChange={(e) => saveModules(file.id, file.modules, e.target.checked)}
            />
            <span>
              I am authorized to review this host. Requests are limited to the homepage, robots.txt, sitemap.xml, and security.txt.
            </span>
          </label>
        ) : null}
        <div className="mt-4 flex flex-col gap-2 border-t border-line pt-4 sm:flex-row sm:items-end">
          <label className="block text-xs text-faint sm:w-40">
            Watch schedule
            <SelectInput className="mt-1" value={schedule} onChange={(e) => setSchedule(e.target.value as Schedule)}>
              <option value="hourly">Hourly</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
            </SelectInput>
          </label>
          <Button
            type="button"
            variant="line"
            onClick={() => {
              const chosen = schedule;
              upsertMonitor(file.id, chosen, file.modules, true);
              toast(`Watching ${file.name} ${chosen}`);
            }}
          >
            {monitor ? "Update monitor" : "Create monitor"}
          </Button>
          {monitor ? (
            <Button type="button" variant="ghost" onClick={() => removeMonitor(monitor.id)}>
              Remove monitor
            </Button>
          ) : null}
          {monitor ? <p className="text-xs text-muted sm:ml-auto sm:pb-3">Last delta: {monitor.lastDelta}</p> : null}
        </div>
      </details>

      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex gap-1 overflow-x-auto" role="tablist">
          {(lens === "technical" ? TABS : TABS.filter((name) => name !== "Graph")).map((name) => (
            <button
              key={name}
              type="button"
              role="tab"
              aria-selected={tab === name}
              onClick={() => setTab(name)}
              className={
                tab === name
                  ? "min-h-11 shrink-0 rounded-lg bg-accent px-3 text-sm font-medium text-accent-fg"
                  : "min-h-11 shrink-0 rounded-lg px-3 text-sm text-muted hover:bg-subtle hover:text-fg"
              }
            >
              {name}
            </button>
          ))}
        </div>
        <RangeControls range={range} onChange={setRange} />
      </div>

      {tab === "Overview" ? (
        <div className="space-y-4">
          <Panel>
            <h2 className="text-base font-medium">Top priorities</h2>
            <p className="mt-1 text-sm text-muted">The items worth acting on first. Info rows stay on Findings.</p>
            {priorities.length ? (
              <ul className="mt-3 divide-y divide-line">
                {priorities.map((entity) => {
                  const shown = displayEntity(entity, showDetails);
                  return (
                    <li key={entity.id} className="py-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <RiskPill level={riskOf(entity)} />
                        <p className="text-sm font-medium text-fg">{shown.title}</p>
                      </div>
                      <p className="mt-1 text-sm text-muted">{lens === "simple" ? howToFix(entity) : whatItMeans(entity)}</p>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="mt-3 text-sm text-muted">{ranked.length ? "Nothing above Info in this window." : "Start the scan to fill this list."}</p>
            )}
          </Panel>
          <div className="grid gap-4 lg:grid-cols-2">
            <Panel>
              <h2 className="mb-2 text-base font-medium">New items</h2>
              <DayLine data={seriesByDay(file.entities.filter((e) => e.meta.role !== "subject"), bounds.from, bounds.to)} />
            </Panel>
            <Panel>
              <h2 className="mb-2 text-base font-medium">By type</h2>
              <CountBars data={countsByType(entities).map((d) => ({ label: d.type, count: d.count }))} />
            </Panel>
          </div>
          {lens === "technical" ? (
            <Panel>
              <h2 className="text-base font-medium">Trend notes</h2>
              <ul className="mt-2 space-y-1 text-sm text-muted">
                {notesTrend.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </Panel>
          ) : null}
          <Panel>
            <h2 className="text-base font-medium">Notes</h2>
            <TextArea className="mt-2 min-h-24" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="What you are allowed to test, and why this target is in scope." />
            <Button type="button" className="mt-2" variant="line" onClick={() => saveNotes(file.id, notes)}>
              Save notes
            </Button>
          </Panel>
        </div>
      ) : null}

      {tab === "Findings" ? (
        <Panel>
          <div className="mb-3 flex flex-wrap gap-2">
            {(["All", "Critical", "High", "Medium", "Low", "Info"] as const).map((level) => (
              <button
                key={level}
                type="button"
                onClick={() => setRiskFilter(level)}
                className={riskFilter === level ? "min-h-11 rounded-lg bg-accent px-3 text-sm font-medium text-accent-fg" : "min-h-11 rounded-lg border border-line px-3 text-sm text-muted"}
              >
                {level}
                {level === "All" ? "" : ` ${counts[level]}`}
              </button>
            ))}
          </div>
          <ul className="divide-y divide-line">
            {ranked
              .filter((entity) => riskFilter === "All" || riskOf(entity) === riskFilter)
              .map((entity) => {
                const shown = displayEntity(entity, showDetails);
                return (
                  <li key={entity.id}>
                    <details className="group py-1">
                      <summary className="flex min-h-11 cursor-pointer list-none items-center gap-3 py-2 [&::-webkit-details-marker]:hidden">
                        <RiskPill level={riskOf(entity)} />
                        <span className="min-w-0 flex-1">
                          <span className="block text-sm text-fg">{shown.title}</span>
                          {lens === "technical" ? <span className="block break-all font-mono text-xs text-faint">{shown.value}</span> : null}
                        </span>
                        <span className="text-xs text-faint">{entity.historical ? "Historical" : "Current"}</span>
                      </summary>
                      <div className="grid gap-3 pb-3 sm:grid-cols-2">
                        {shown.photo ? <img src={shown.photo} alt="" className="size-16 rounded-lg object-cover" referrerPolicy="no-referrer" /> : null}
                        <div>
                          <p className="text-xs uppercase tracking-wide text-faint">What was observed</p>
                          <p className="mt-1 text-sm text-muted">{whatItMeans(entity)}</p>
                          {shown.lines.map((line) => (
                            <p key={line} className="mt-1 text-sm text-muted">{line}</p>
                          ))}
                        </div>
                        <div>
                          <p className="text-xs uppercase tracking-wide text-faint">How to fix</p>
                          <p className="mt-1 text-sm text-muted">{howToFix(entity)}</p>
                          {lens === "technical" ? (
                            <p className="mt-2 font-mono text-xs text-faint">
                              {entity.source} · {entity.relation} · {entity.type}
                              {entity.meta.missingFrom ? " · not reconfirmed" : ""}
                            </p>
                          ) : null}
                          {entity.meta.role === "subject" ? null : (
                            <button type="button" className="mt-2 text-xs text-muted underline" onClick={() => removeEntity(file.id, entity.id)}>
                              Remove from this scan
                            </button>
                          )}
                        </div>
                      </div>
                    </details>
                  </li>
                );
              })}
          </ul>
          {!ranked.filter((entity) => riskFilter === "All" || riskOf(entity) === riskFilter).length ? (
            <p className="text-sm text-muted">Nothing in this rating for the current date window.</p>
          ) : null}
        </Panel>
      ) : null}

      {tab === "Assets" ? (
        <Panel>
          <AssetTable
            rows={ranked.filter((entity) => entity.type === "domain" || entity.type === "subdomain" || entity.type === "ip" || entity.type === "asn" || entity.type === "tech" || entity.type === "port")}
            showDetails={showDetails}
          />
        </Panel>
      ) : null}

      {tab === "Leaks" ? (
        <ExposureBoard
          rows={exposureRows(file, entities, showDetails).filter((row) => row.bucket === "exposed")}
          checksReady={catalog.length}
          checksFinished={lastScan && lastScan.status !== "running" ? lastScan.modules.length : null}
          brokerCount={TAKEDOWN_LINKS.filter((link) => link.group === "Data brokers").length}
          onOpenBrokers={() => setTab("Footprint")}
        />
      ) : null}

      {tab === "Graph" ? (
        <Panel>
          <GraphPanel
            entities={showDetails ? entities : entities.map((entity) => ({ ...entity, title: displayEntity(entity, false).title, value: displayEntity(entity, false).value }))}
            edges={file.edges}
          />
        </Panel>
      ) : null}

      {tab === "Footprint" ? (
        <div className="space-y-4">
          <Panel>
            <h2 className="text-base font-medium">Public profiles and published contacts</h2>
            <p className="mt-1 text-sm text-muted">
              These come from profile APIs and domain registration. Turn on public details in Settings to unmask a phone, address, or photo the registry already published.
            </p>
            <ul className="mt-3 divide-y divide-line">
              {ranked
                .filter((entity) => entity.type === "profile" || entity.relation.startsWith("published-") || entity.type === "email" || entity.type === "username")
                .slice(0, 40)
                .map((entity) => {
                  const shown = displayEntity(entity, showDetails);
                  return (
                    <li key={entity.id} className="flex items-start gap-3 py-2">
                      {shown.photo ? <img src={shown.photo} alt="" className="size-10 rounded-lg object-cover" referrerPolicy="no-referrer" /> : null}
                      <div>
                        <p className="text-sm text-fg">{shown.title}</p>
                        <p className="text-xs text-faint">{entity.source}</p>
                      </div>
                    </li>
                  );
                })}
            </ul>
          </Panel>
          <Panel>
            <h2 className="text-base font-medium">Where a Social Security number shows up</h2>
            <p className="mt-2 text-sm leading-relaxed text-muted">
              This workstation does not look up or display a Social Security number. Certificate logs, DNS, domain registration, and public profile APIs do not publish one.
            </p>
            <ul className="mt-3 space-y-2 text-sm text-muted">
              <li>People-search sites publish names, ages, addresses, phones, and sometimes relatives. A full Social Security number is not on the free public listing. Paid background checks sometimes sell a trace behind an account. That is not an open page, and it is not fetched here.</li>
              <li>Have I Been Pwned can say a breach included the category “Social security numbers.” It does not return the number. Stolen copies move on closed forums, not in a public directory.</li>
              <li>Old court PDFs, recorder filings, and UCC documents sometimes contain a full or partial number by mistake. Search your own name on the court or county site and ask the clerk to redact the filing. Google can drop the search result. That does not delete the document.</li>
              <li>Your own Social Security record is on the Social Security Administration site after you sign in. Death records list numbers for people who have died, not a living person’s open listing.</li>
            </ul>
            <p className="mt-3 text-sm text-muted">
              If you think yours was copied, freeze credit at all three bureaus, read the free credit report, and use IdentityTheft.gov if someone is already using it. A breach row in this case only means a category was named
              {entities.some((entity) => /social security|ssn|government id|national id|passport/i.test(entity.meta.classes ?? ""))
                ? ", and this investigation already has a breach category that mentions a government identifier."
                : ". This investigation does not currently have a breach category that mentions a government identifier."}
            </p>
          </Panel>
          <Panel>
            <h2 className="text-base font-medium">How to take a listing down</h2>
            <p className="mt-2 text-sm text-muted">
              These steps remove data from the website or broker that published it. Clearing this browser does not.
            </p>
            <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm text-muted">
              {TAKEDOWN_METHOD.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
          </Panel>
          <Panel>
            <h2 className="text-base font-medium">Send a removal request</h2>
            <p className="mt-1 text-sm text-muted">
              Spokeo, BeenVerified, and Whitepages publish a privacy mailbox. This opens that message in your mail app, or opens the broker’s form. Footprint cannot pass a captcha or click the confirmation link the broker sends you.
            </p>
            <div className="mt-3 grid gap-2 sm:grid-cols-3">
              <TextInput value={removeName} onChange={(e) => setRemoveName(e.target.value)} placeholder="Name on the listing" aria-label="Name on the listing" />
              <TextInput value={removeEmail} onChange={(e) => setRemoveEmail(e.target.value)} placeholder="Email you can confirm" aria-label="Email for the broker confirmation" inputMode="email" />
              <TextInput value={listingUrl} onChange={(e) => setListingUrl(e.target.value)} placeholder="https:// listing URL" aria-label="Listing URL" inputMode="url" />
            </div>
            {(file.removals ?? []).length ? (
              <ul className="mt-3 space-y-1 text-xs text-muted">
                {(file.removals ?? []).slice(0, 8).map((row) => (
                  <li key={`${row.at}-${row.broker}`}>
                    {format(new Date(row.at), "d MMM HH:mm")} · {row.broker} · {row.channel === "mail" ? "opened in your mail app" : "official form opened"}
                  </li>
                ))}
              </ul>
            ) : null}
          </Panel>
          {["Search engines", "Data brokers", "Phones, mail, and credit"].map((group) => (
            <Panel key={group}>
              <h2 className="text-base font-medium">{group}</h2>
              <ul className="mt-3 space-y-3">
                {TAKEDOWN_LINKS.filter((link) => link.group === group).map((link) => (
                  <li key={link.href} className="border-b border-line pb-3">
                    <p className="text-sm font-medium text-fg">{link.title}</p>
                    <p className="mt-1 text-sm text-muted">{link.detail}</p>
                    <div className="mt-1 flex flex-wrap gap-3">
                      {link.mail ? (
                        <button type="button" className="min-h-11 text-sm text-info" onClick={() => requestRemoval(link, "mail")}>
                          Email {link.mail}
                        </button>
                      ) : null}
                      <button type="button" className="min-h-11 text-sm text-info" onClick={() => requestRemoval(link, "form")}>
                        Open official form
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            </Panel>
          ))}
          <Panel>
            <h2 className="text-base font-medium">Letter if the form is ignored</h2>
            <p className="mt-1 text-sm text-muted">
              Send this to the site’s privacy contact for {file.target}. Attach the listing URL. Do not attach an identity number.
            </p>
            <Button
              type="button"
              className="mt-3"
              variant="line"
              onClick={() => {
                const letter = removalLetter({
                  target: file.target,
                  kind: file.kind,
                  name: removeName,
                  email: removeEmail,
                  listingUrl,
                });
                void navigator.clipboard.writeText(letter).then(
                  () => toast("Takedown request copied"),
                  () => toast("Could not copy. Select the letter below."),
                );
              }}
            >
              Copy takedown request
            </Button>
            <pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap rounded-2xl bg-bg p-3 font-mono text-xs text-muted">
              {removalLetter({
                target: file.target,
                kind: file.kind,
                name: removeName,
                email: removeEmail,
                listingUrl,
              })}
            </pre>
          </Panel>
        </div>
      ) : null}

      {tab === "Report" ? (
        <Panel>
          <p className="max-w-xl text-sm text-muted">
            Exports use {rangeLabel(range).toLowerCase()} and include the legal notice. HTML is a standalone file. The live graph stays in the app.
            {showDetails
              ? " Public details are included because that switch is on."
              : " Published phones, addresses, photos, and breach categories stay masked until you turn public details on and save."}
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <Button type="button" variant="line" onClick={() => download(`${stamp}.md`, reportMarkdown(file, entities, notesTrend, range, showDetails), "text/markdown")}>
              Markdown
            </Button>
            <Button type="button" variant="line" onClick={() => download(`${stamp}.json`, reportJson(file, entities, notesTrend, range, showDetails), "application/json")}>
              JSON
            </Button>
            <Button type="button" variant="line" onClick={() => download(`${stamp}.csv`, reportCsv(entities, showDetails), "text/csv")}>
              CSV
            </Button>
            <Button type="button" variant="line" onClick={() => download(`${stamp}.html`, reportHtml(file, entities, notesTrend, range, showDetails), "text/html")}>
              HTML
            </Button>
          </div>
          <div className="mt-4 flex flex-wrap gap-2 border-t border-line pt-4">
            <Button
              type="button"
              variant="ghost"
              onClick={() => {
                const n = purgeHistorical(file.id);
                toast(`Removed ${n} historical entities`);
              }}
            >
              Remove historical entities
            </Button>
          </div>
          {file.scans[0]?.log && lens === "technical" ? (
            <pre className="mt-4 max-h-80 overflow-auto whitespace-pre-wrap rounded-2xl bg-bg p-3 font-mono text-xs text-muted">{showDetails ? file.scans[0].log : maskText(file.scans[0].log)}</pre>
          ) : null}
          <h3 className="mt-6 text-sm font-medium text-fg">Scan history</h3>
          <ul className="mt-2 space-y-2">
            {scans.length ? scans.map((s) => (
              <li key={s.id} className="text-sm text-muted">
                <span className="text-fg">{s.reason === "monitor" ? "Monitor" : "Manual"} · {s.status}</span>
                {" · "}
                {format(new Date(s.startedAt), "d MMM yyyy HH:mm")} · {s.summary}
              </li>
            )) : <li className="text-sm text-muted">No scans in this window.</li>}
          </ul>
          {lens === "technical" ? (
            <ul className="mt-4 max-h-64 space-y-1 overflow-auto">
              {logs.slice(0, 40).map((l) => (
                <li key={l.id} className="font-mono text-xs text-faint">
                  {format(new Date(l.ts), "d MMM HH:mm:ss")} {l.action} {showDetails ? l.message : maskText(l.message)}
                </li>
              ))}
            </ul>
          ) : null}
        </Panel>
      ) : null}
    </Shell>
  );
}

function RangeControls({ range, onChange }: { range: DateRange; onChange: (r: DateRange) => void }) {
  const presets: DateRange["preset"][] = ["7", "30", "90", "all", "custom"];
  return (
    <div className="flex flex-wrap items-center gap-2">
      {presets.map((p) => (
        <button
          key={p}
          type="button"
          onClick={() => onChange({ ...range, preset: p })}
          className={
            range.preset === p
              ? "min-h-11 rounded-lg bg-subtle px-3 text-sm text-fg"
              : "min-h-11 rounded-lg px-3 text-sm text-muted hover:bg-subtle"
          }
        >
          {p === "all" ? "All" : p === "custom" ? "Custom" : `${p}d`}
        </button>
      ))}
      {range.preset === "custom" ? (
        <>
          <input
            type="date"
            value={range.from}
            onChange={(e) => onChange({ ...range, from: e.target.value })}
            className="min-h-11 rounded-lg border border-line bg-subtle px-2 text-sm"
            aria-label="From date"
          />
          <input
            type="date"
            value={range.to}
            onChange={(e) => onChange({ ...range, to: e.target.value })}
            className="min-h-11 rounded-lg border border-line bg-subtle px-2 text-sm"
            aria-label="To date"
          />
        </>
      ) : null}
    </div>
  );
}

function RiskPill({ level }: { level: RiskLevel }) {
  return <span className={`inline-flex shrink-0 rounded-md px-1.5 py-0.5 text-xs font-medium ${riskTone(level)}`}>{level}</span>;
}

function riskTone(level: RiskLevel): string {
  if (level === "Critical" || level === "High") return "bg-danger/15 text-danger";
  if (level === "Medium") return "bg-warn/15 text-warn";
  if (level === "Low") return "bg-info/15 text-info";
  return "bg-subtle text-muted";
}

function riskBlurb(level: RiskLevel): string {
  if (level === "Critical") return "Account data or a malware association is public. Treat the named breaches as real until you have changed those passwords.";
  if (level === "High") return "A phone, street address, or open port is published. Fix these before the informational rows.";
  if (level === "Medium") return "Configuration gaps. None of them prove a break-in from public data alone.";
  if (level === "Low") return "Hardening, mostly response headers.";
  return "Nothing above an informational row in this window.";
}

function AssetTable({ rows, showDetails }: { rows: Entity[]; showDetails: boolean }) {
  if (!rows.length) return <p className="text-sm text-muted">No hosts, addresses, or technologies in this window.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[36rem] text-left text-sm">
        <thead className="text-xs uppercase tracking-wide text-faint">
          <tr>
            <th className="py-2 pr-3 font-medium">Asset</th>
            <th className="py-2 pr-3 font-medium">Kind</th>
            <th className="py-2 font-medium">Source</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((entity) => {
            const shown = displayEntity(entity, showDetails);
            return (
              <tr key={entity.id} className="border-t border-line">
                <td className="py-2 pr-3">
                  <div className="text-fg">{shown.title}</div>
                  <div className="break-all font-mono text-xs text-faint">{shown.value}</div>
                </td>
                <td className="py-2 pr-3 text-xs text-muted">{entity.type}</td>
                <td className="py-2 text-xs text-muted">{entity.source}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
