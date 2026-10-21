import { parsePhoneNumberFromString, type CountryCode } from "libphonenumber-js";

import type { ModuleResult } from "@/lib/osint/types";

/**
 * Numbering-plan metadata only, the same class of fact GhostTrack prints
 * from its offline phone library. This is not a device location.
 */
export function phoneResult(raw: string): ModuleResult {
  const started = Date.now();
  const trimmed = raw.trim();
  let parsed = parsePhoneNumberFromString(trimmed);
  let assumed: CountryCode | "" = "";
  if (!parsed?.isPossible() && /^\d{10}$/.test(trimmed.replace(/\D/g, "")) && !trimmed.startsWith("+")) {
    parsed = parsePhoneNumberFromString(trimmed, "US");
    assumed = "US";
  }
  if (!parsed) {
    return {
      module: "phone",
      ok: false,
      truncated: false,
      error: "That number could not be parsed. Include a country code, such as +1.",
      durationMs: Date.now() - started,
      entities: [],
      log: ["Phone parse failed."],
    };
  }
  const type = parsed.getType() ?? "unknown";
  const region = parsed.country ?? assumed ?? "";
  const title = parsed.formatInternational();
  return {
    module: "phone",
    ok: true,
    truncated: false,
    durationMs: Date.now() - started,
    entities: [
      {
        type: "phone",
        value: parsed.number,
        severity: "info",
        relation: "numbering-plan",
        source: "phone",
        title,
        meta: {
          country: region || "unknown",
          callingCode: parsed.countryCallingCode,
          type,
          valid: parsed.isValid() ? "yes" : "possible only",
          assumed: assumed ? "Read as a US number because no country code was given." : "",
          note: "Country and line type come from the public numbering plan. This is not where a handset is.",
        },
      },
    ],
    log: [
      `${title} · ${region || "country unknown"} · ${type}.`,
      "No carrier lookup and no live location. A phone number does not reveal a street address from here.",
    ],
  };
}
