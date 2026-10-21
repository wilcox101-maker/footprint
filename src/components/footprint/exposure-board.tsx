import { useState } from "react";

import type { ExposureRow } from "@/lib/osint/exposure";

const COLUMNS = ["Source", "Password", "Email", "Username", "IP", "Phone", "Birthdate", "Address"] as const;

type Filter = "all" | ExposureRow["bucket"];

export function ExposureBoard({
  rows,
  checksReady,
  checksFinished,
  brokerCount,
  onOpenBrokers,
}: {
  rows: ExposureRow[];
  checksReady: number;
  checksFinished: number | null;
  brokerCount: number;
  onOpenBrokers: () => void;
}) {
  const [filter, setFilter] = useState<Filter>("all");
  const profiles = rows.filter((row) => row.bucket === "profiles").length;
  const records = rows.filter((row) => row.bucket === "records").length;
  const exposed = rows.filter((row) => row.bucket === "exposed").length;
  const visible = filter === "all" ? rows : rows.filter((row) => row.bucket === filter);

  const cards: { id: Filter | "brokers"; title: string; count: number }[] = [
    { id: "profiles", title: "Social Media Profiles", count: profiles },
    { id: "records", title: "Public Records", count: records },
    { id: "exposed", title: "Exposed Data", count: exposed },
    { id: "brokers", title: "Data Brokers", count: brokerCount },
  ];

  return (
    <div className="space-y-4">
      <p className="flex items-center gap-2 text-sm text-info">
        <span aria-hidden="true">{checksFinished !== null ? "✓" : "•"}</span>
        {checksFinished !== null
          ? `${checksFinished} security checks finished`
          : `${checksReady} security checks ready`}
      </p>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {cards.map((card) => {
          const selected = card.id !== "brokers" && filter === card.id;
          return (
            <button
              key={card.title}
              type="button"
              onClick={() => {
                if (card.id === "brokers") onOpenBrokers();
                else setFilter(filter === card.id ? "all" : card.id);
              }}
              className={
                selected
                  ? "min-h-24 rounded-2xl border border-info bg-[#152033] px-4 py-4 text-left"
                  : "min-h-24 rounded-2xl border border-transparent bg-[#152033] px-4 py-4 text-left hover:border-line"
              }
            >
              <span className="block text-base font-semibold text-fg">{card.title}</span>
              <span className="mt-2 block font-mono text-2xl tabular-nums text-fg">{card.count}</span>
            </button>
          );
        })}
      </div>
      <div className="overflow-x-auto rounded-2xl border border-line bg-[#101820]">
        <table className="w-full min-w-[56rem] text-left text-sm">
          <thead className="text-xs text-muted">
            <tr>
              {COLUMNS.map((column) => (
                <th key={column} className="px-3 py-3 font-medium">
                  {column}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map((row) => (
              <tr key={row.id} className={row.flagged ? "border-t border-line border-l-2 border-l-danger" : "border-t border-line border-l-2 border-l-transparent"}>
                <td className="px-3 py-3 text-fg">{row.source}</td>
                <td className="px-3 py-3 text-muted">{row.password}</td>
                <td className="px-3 py-3 text-muted">{row.email}</td>
                <td className="px-3 py-3 text-muted">{row.username}</td>
                <td className="px-3 py-3 font-mono text-xs text-muted">{row.ip}</td>
                <td className="px-3 py-3 text-muted">{row.phone}</td>
                <td className="px-3 py-3 text-muted">{row.birthdate}</td>
                <td className="px-3 py-3 text-muted">{row.address}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!visible.length ? <p className="px-3 py-4 text-sm text-muted">Nothing in this group yet. Start a scan, or pick another card.</p> : null}
      </div>
      <p className="text-xs leading-relaxed text-faint">
        Password values are not collected. If a breach index says passwords were included, that cell says Not retrieved. Birthdate is not looked up. Emails and published contacts stay masked until public details are on.
      </p>
    </div>
  );
}
