import { moduleDef } from "@/lib/osint/catalog";
import { dorkResult, pivotResult } from "@/lib/osint/dorks";
import { phoneResult } from "@/lib/osint/phone";
import { hostFrom } from "@/lib/osint/guard";
import { runModules } from "@/lib/osint/recon.functions";
import {
  applyModuleResult,
  beginScan,
  dueMonitors,
  finishScan,
  getCase,
  loadVault,
  markMonitorRun,
} from "@/lib/osint/store";
import type { ModuleResult } from "@/lib/osint/types";

let busy = false;

export function runBusy() {
  return busy;
}

function failed(module: string, message: string): ModuleResult {
  return { module, ok: false, truncated: false, error: message, durationMs: 0, entities: [], log: [message] };
}

export async function runCase(
  caseId: string,
  reason: "manual" | "monitor",
  onProgress?: (message: string) => void,
): Promise<{ ok: boolean; message: string; highs: number }> {
  if (busy) return { ok: false, message: "A run is already in progress.", highs: 0 };
  const file = getCase(caseId);
  if (!file) return { ok: false, message: "That investigation is gone.", highs: 0 };
  const modules = file.modules.filter((id) => moduleDef(id)?.kinds.includes(file.kind));
  if (!modules.length) {
    if (reason === "monitor") markMonitorRun(caseId, "No modules selected", "error");
    return { ok: false, message: "Pick at least one module.", highs: 0 };
  }
  if (modules.includes("surface") && !file.authorized) {
    if (reason === "monitor") markMonitorRun(caseId, "Authorization required", "error");
    return { ok: false, message: "Confirm authorization before a surface review.", highs: 0 };
  }

  busy = true;
  const scanId = beginScan(caseId, modules, reason);
  const settings = loadVault().settings;
  try {
    for (const id of modules) {
      const label = moduleDef(id)?.label ?? id;
      onProgress?.(`Running ${label}`);
      let results: ModuleResult[] = [];
      try {
        if (id === "dorks") {
          const host = hostFrom(file.kind, file.target);
          results = [dorkResult(host || file.target)];
        } else if (id === "pivots") {
          const host = hostFrom(file.kind, file.target);
          results = [pivotResult(file.kind, file.target, host || file.target)];
        } else if (id === "phone") {
          results = [phoneResult(file.target)];
        } else {
          const response = await runModules({
            data: {
              target: file.target,
              kind: file.kind,
              modules: [id],
              authorized: file.authorized,
              hibpKey: id === "breach" ? settings.hibpKey : "",
              vtKey: id === "reputation" ? settings.vtKey : "",
            },
          });
          results = response.results;
        }
      } catch (error) {
        results = [failed(id, error instanceof Error ? error.message : "Lookup failed")];
      }
      if (!results.length) results = [failed(id, "No result")];
      for (const result of results) applyModuleResult(caseId, scanId, result);
    }
    finishScan(caseId, scanId);
    const done = getCase(caseId);
    const scan = done?.scans.find((s) => s.id === scanId);
    const highs =
      done?.entities.filter((e) => e.severity === "high" && scan && e.firstSeen >= scan.startedAt).length ?? 0;
    const message = scan?.summary ?? "Finished";
    if (reason === "monitor") markMonitorRun(caseId, message, scan?.status ?? "error");
    return { ok: scan?.status !== "error", message, highs };
  } finally {
    busy = false;
  }
}

export async function runDueMonitor(onProgress?: (message: string) => void) {
  if (busy) return null;
  const next = dueMonitors()[0];
  if (!next) return null;
  const file = getCase(next.caseId);
  if (!file) return null;
  onProgress?.(`Monitor · ${file.name}`);
  return { file, result: await runCase(next.caseId, "monitor", onProgress) };
}
