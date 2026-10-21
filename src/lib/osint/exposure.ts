import type { CaseFile, Entity } from "@/lib/osint/types";
import { maskText } from "@/lib/osint/sensitive";

export type ExposureBucket = "profiles" | "records" | "exposed";

export type ExposureRow = {
  id: string;
  bucket: ExposureBucket;
  source: string;
  password: string;
  email: string;
  username: string;
  ip: string;
  phone: string;
  birthdate: string;
  address: string;
  flagged: boolean;
};

const DASH = "—";

function shown(value: string | undefined, show: boolean): string {
  const text = (value ?? "").trim();
  if (!text) return DASH;
  return show ? text : maskText(text);
}

function passwordCell(classes: string | undefined): string {
  if (classes && /password/i.test(classes)) return "Not retrieved";
  return DASH;
}

/** Rows for the exposed-data table. Password material is never copied into a cell. */
export function exposureRows(file: CaseFile, entities: Entity[], show: boolean): ExposureRow[] {
  const rows: ExposureRow[] = [];
  const targetEmail = file.kind === "email" ? file.target : "";
  const targetUser = file.kind === "username" ? file.target : "";

  for (const entity of entities) {
    if (entity.meta.role === "subject") continue;
    if (entity.type === "breach" || entity.relation === "breach-title") {
      rows.push({
        id: entity.id,
        bucket: "exposed",
        source: entity.title.replace(/\s*\([^)]*\)\s*$/, "").trim() || entity.source,
        password: passwordCell(entity.meta.classes),
        email: shown(entity.meta.email || targetEmail, show),
        username: shown(entity.meta.username, show),
        ip: DASH,
        phone: DASH,
        birthdate: DASH,
        address: DASH,
        flagged: /password|social security|ssn/i.test(entity.meta.classes ?? "") || entity.severity !== "info",
      });
      continue;
    }
    if (entity.type === "profile" || entity.relation === "profile" || entity.relation === "gravatar") {
      const site = entity.meta.site || entity.title.split(":")[0]?.trim() || entity.source;
      const user = entity.title.includes(":") ? entity.title.split(":").slice(1).join(":").trim() : targetUser;
      rows.push({
        id: entity.id,
        bucket: "profiles",
        source: site,
        password: DASH,
        email: shown(targetEmail, show),
        username: shown(user || targetUser, show),
        ip: DASH,
        phone: DASH,
        birthdate: DASH,
        address: shown(entity.meta.location, show),
        flagged: false,
      });
      continue;
    }
    if (entity.relation === "published-email" || entity.relation === "published-phone" || entity.relation === "published-address") {
      rows.push({
        id: entity.id,
        bucket: "records",
        source: "Domain registration",
        password: DASH,
        email: shown(entity.relation === "published-email" ? entity.value : "", show),
        username: DASH,
        ip: DASH,
        phone: shown(entity.relation === "published-phone" ? entity.value : "", show),
        birthdate: DASH,
        address: shown(entity.relation === "published-address" ? entity.value : "", show),
        flagged: true,
      });
    }
  }
  return rows;
}
