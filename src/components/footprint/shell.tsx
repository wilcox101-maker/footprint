import { Link } from "@tanstack/react-router";
import { useEffect } from "react";
import { toast } from "sonner";

import { LEGAL } from "@/lib/osint/types";
import { runDueMonitor } from "@/lib/osint/run-client";
import { useVault } from "@/lib/osint/use-vault";

export function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-bg text-fg lg:grid lg:grid-cols-[14.5rem_minmax(0,1fr)]">
      <MonitorTick />
      <aside className="border-b border-line lg:sticky lg:top-0 lg:flex lg:h-screen lg:flex-col lg:border-b-0 lg:border-r">
        <Link to="/" className="flex items-center gap-2 px-4 py-4 text-fg no-underline">
          <span
            className="grid size-9 shrink-0 grid-rows-[1fr_auto] rounded-[4px] border border-[#3d4e60] bg-[#1a3348] px-0.5 pb-0.5 pt-1 leading-none"
            aria-hidden="true"
          >
            <span className="self-center text-center text-[15px] font-medium tracking-tight text-fg">Fp</span>
            <span className="truncate text-center text-[6px] font-medium uppercase tracking-wide text-[#8eabc4]">Footprint</span>
          </span>
          <span className="text-base font-medium tracking-tight">Footprint</span>
        </Link>
        <nav className="flex gap-1 px-2 pb-3 lg:flex-col">
          <Link
            to="/"
            className="inline-flex min-h-11 items-center rounded-lg px-3 text-sm text-muted hover:bg-subtle hover:text-fg"
            activeOptions={{ exact: true }}
            activeProps={{ className: "inline-flex min-h-11 items-center rounded-lg bg-subtle px-3 text-sm text-fg" }}
          >
            Scans
          </Link>
          <Link
            to="/settings"
            className="inline-flex min-h-11 items-center rounded-lg px-3 text-sm text-muted hover:bg-subtle hover:text-fg"
            activeProps={{ className: "inline-flex min-h-11 items-center rounded-lg bg-subtle px-3 text-sm text-fg" }}
          >
            Settings
          </Link>
        </nav>
        <p className="mt-auto hidden px-4 pb-4 text-xs leading-relaxed text-faint lg:block">{LEGAL}</p>
      </aside>
      <div className="min-w-0">
        <p className="border-b border-line px-4 py-2 text-xs leading-relaxed text-faint lg:sr-only">{LEGAL}</p>
        <main className="mx-auto max-w-6xl px-4 py-6">{children}</main>
      </div>
    </div>
  );
}

function MonitorTick() {
  const { ready } = useVault();
  useEffect(() => {
    if (!ready) return;
    let stop = false;
    const tick = async () => {
      if (stop) return;
      const ran = await runDueMonitor();
      if (!ran || stop) return;
      if (ran.result.highs > 0) {
        toast.warning(`${ran.file.name}: ${ran.result.highs} new high-severity item${ran.result.highs === 1 ? "" : "s"}`);
      } else {
        toast(`Monitor · ${ran.file.name}: ${ran.result.message}`);
      }
    };
    void tick();
    const id = window.setInterval(() => void tick(), 60_000);
    return () => {
      stop = true;
      window.clearInterval(id);
    };
  }, [ready]);
  return null;
}
