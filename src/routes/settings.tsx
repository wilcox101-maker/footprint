import { createFileRoute } from "@tanstack/react-router";
import { format } from "date-fns";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Shell } from "@/components/footprint/shell";
import { Button, Panel, SelectInput, TextInput } from "@/components/footprint/ui";
import { saveSettings, tidyVault } from "@/lib/osint/store";
import type { LogLevel } from "@/lib/osint/types";
import { LEGAL } from "@/lib/osint/types";
import { useVault } from "@/lib/osint/use-vault";

export const Route = createFileRoute("/settings")({ component: SettingsPage });

function SettingsPage() {
  const { vault, ready } = useVault();
  const [hibp, setHibp] = useState("");
  const [vt, setVt] = useState("");
  const [retention, setRetention] = useState("90");
  const [stale, setStale] = useState("30");
  const [level, setLevel] = useState<LogLevel>("info");
  const [details, setDetails] = useState(false);
  const [logQuery, setLogQuery] = useState("");
  const [confirmTidy, setConfirmTidy] = useState(false);

  useEffect(() => {
    if (!ready) return;
    setHibp(vault.settings.hibpKey);
    setVt(vault.settings.vtKey);
    setRetention(String(vault.settings.retentionDays));
    setStale(String(vault.settings.staleDays));
    setLevel(vault.settings.logLevel);
    setDetails(Boolean(vault.settings.showSensitive));
  }, [ready, vault.settings]);

  const q = logQuery.trim().toLowerCase();
  const logs = vault.logs.filter((l) => !q || l.message.toLowerCase().includes(q) || l.action.includes(q) || l.level.includes(q));

  return (
    <Shell>
      <h1 className="text-2xl font-medium tracking-tight">Settings</h1>
      <p className="mt-1 max-w-2xl text-sm text-muted">
        Everything Footprint stores stays in this browser. Keys are sent only with a lookup you start, and only to the matching vendor.
      </p>

      {!ready ? (
        <div className="mt-4 h-40 animate-pulse rounded-3xl bg-elevated" />
      ) : (
        <div className="mt-5 space-y-5">
          <Panel>
            <h2 className="text-base font-medium">Optional API keys</h2>
            <p className="mt-1 text-sm text-muted">
              Leave these blank to use sources that do not need a key. Have I Been Pwned and VirusTotal are enrichment only. Do not use a shared computer.
            </p>
            <label className="mt-3 block text-xs text-faint">
              Have I Been Pwned
              <TextInput className="mt-1" type="password" value={hibp} autoComplete="off" onChange={(e) => setHibp(e.target.value)} />
            </label>
            <label className="mt-3 block text-xs text-faint">
              VirusTotal
              <TextInput className="mt-1" type="password" value={vt} autoComplete="off" onChange={(e) => setVt(e.target.value)} />
            </label>
            <div className="mt-3 grid gap-3 sm:grid-cols-3">
              <label className="text-xs text-faint">
                Raw log retention (days)
                <TextInput className="mt-1" inputMode="numeric" value={retention} onChange={(e) => setRetention(e.target.value)} />
              </label>
              <label className="text-xs text-faint">
                Mark stale after (days)
                <TextInput className="mt-1" inputMode="numeric" value={stale} onChange={(e) => setStale(e.target.value)} />
              </label>
              <label className="text-xs text-faint">
                Log level
                <SelectInput className="mt-1" value={level} onChange={(e) => setLevel(e.target.value as LogLevel)}>
                  <option value="debug">Debug</option>
                  <option value="info">Info</option>
                  <option value="warn">Warn</option>
                  <option value="error">Error</option>
                </SelectInput>
              </label>
            </div>
            <label className="mt-4 flex items-start gap-2 text-sm text-muted">
              <input
                type="checkbox"
                className="mt-1 size-4 accent-info"
                checked={details}
                onChange={(e) => setDetails(e.target.checked)}
              />
              <span>
                <span className="block text-fg">Show public details</span>
                Show published photos, phone numbers, street addresses, and breach categories on investigations. Off by default, so a shared screen stays masked.
              </span>
            </label>
            <p className="mt-2 text-sm text-muted">
              This does not unlock passwords, Social Security numbers, or family or spouse files. Those values are not requested or stored. A breach can still say that a category such as “passwords” or “government IDs” was included.
            </p>
            <Button
              className="mt-3"
              type="button"
              onClick={() => {
                saveSettings({
                  hibpKey: hibp.trim(),
                  vtKey: vt.trim(),
                  retentionDays: Number(retention) || 90,
                  staleDays: Number(stale) || 30,
                  logLevel: level,
                  showSensitive: details,
                });
                toast("Settings saved in this browser");
              }}
            >
              Save settings
            </Button>
          </Panel>

          <Panel>
            <h2 className="text-base font-medium">Housekeeping</h2>
            <p className="mt-1 text-sm text-muted">
              Tidy drops activity and raw run output older than the retention window, deduplicates entities, and marks anything not seen within the stale window as historical. Summaries stay.
            </p>
            <Button
              className="mt-3"
              type="button"
              variant="line"
              onClick={() => {
                if (!confirmTidy) {
                  setConfirmTidy(true);
                  return;
                }
                const result = tidyVault();
                setConfirmTidy(false);
                toast(`Trimmed ${result.rawTrimmed} runs, removed ${result.logsRemoved} logs, marked ${result.marked} stale`);
              }}
            >
              {confirmTidy ? "Confirm tidy" : "Tidy stored data"}
            </Button>
          </Panel>

          <Panel>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-base font-medium">Activity log</h2>
              <TextInput
                value={logQuery}
                onChange={(e) => setLogQuery(e.target.value)}
                placeholder="Filter log"
                aria-label="Filter log"
                className="max-w-xs"
              />
            </div>
            <ul className="mt-3 max-h-[28rem] space-y-2 overflow-auto">
              {logs.slice(0, 300).map((l) => (
                <li key={l.id} className="grid gap-1 border-b border-line py-2 text-sm sm:grid-cols-[9rem_4rem_1fr]">
                  <span className="font-mono text-xs text-faint">{format(new Date(l.ts), "d MMM HH:mm:ss")}</span>
                  <span className="font-mono text-xs uppercase text-muted">{l.level}</span>
                  <span>
                    <span className="text-faint">{l.action}</span> {l.message}
                  </span>
                </li>
              ))}
              {!logs.length ? <li className="text-sm text-muted">No log lines yet.</li> : null}
            </ul>
          </Panel>

          <Panel>
            <h2 className="text-base font-medium">Scope and liability</h2>
            <p className="mt-2 text-sm leading-relaxed text-muted">{LEGAL}</p>
            <p className="mt-3 text-sm leading-relaxed text-muted">
              Footprint wraps public registration data, certificate logs, DNS, archives, breach titles, and profile APIs. It does not run Nuclei, Naabu, ffuf, or password-reset checks. Breach modules return titles and data categories only — never passwords, Social Security numbers, or dump contents. The Removal tab lists official opt-out and takedown pages for search engines and data brokers. It does not search for a Social Security number.
            </p>
          </Panel>
        </div>
      )}
    </Shell>
  );
}
