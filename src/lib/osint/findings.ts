import type { Entity } from "@/lib/osint/types";

export const RISK_LEVELS = ["Critical", "High", "Medium", "Low", "Info"] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

const RANK: Record<RiskLevel, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };

/** Map a stored row onto the five-level scale used by a digital-footprint scan. */
export function riskOf(entity: Entity): RiskLevel {
  if (entity.meta.role === "subject") return "Info";
  if (
    entity.type === "cve" ||
    entity.relation === "listed-cve" ||
    entity.relation === "malware-association" ||
    entity.relation === "malware-sample" ||
    entity.type === "breach" ||
    entity.relation === "breach-title" ||
    entity.relation === "blocklist"
  ) {
    return "Critical";
  }
  if (entity.relation === "published-phone" || entity.relation === "published-address" || entity.relation === "listed-port") {
    return "High";
  }
  if (entity.relation === "mail-gap" || entity.relation === "published-email" || entity.relation === "disposable-domain") {
    return "Medium";
  }
  if (entity.relation === "header-gap" || entity.relation === "cookie-gap") return "Low";
  if (entity.severity === "high") return "High";
  if (entity.severity === "medium") return "Medium";
  if (entity.severity === "low") return "Low";
  return "Info";
}

export function overallRisk(entities: Entity[]): RiskLevel {
  let best: RiskLevel = "Info";
  for (const entity of entities) {
    const level = riskOf(entity);
    if (RANK[level] > RANK[best]) best = level;
  }
  return best;
}

export function riskCounts(entities: Entity[]): Record<RiskLevel, number> {
  const counts: Record<RiskLevel, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const entity of entities) {
    if (entity.meta.role === "subject") continue;
    counts[riskOf(entity)] += 1;
  }
  return counts;
}

export function byRisk(entities: Entity[]): Entity[] {
  return entities
    .filter((entity) => entity.meta.role !== "subject")
    .slice()
    .sort((a, b) => RANK[riskOf(b)] - RANK[riskOf(a)] || a.title.localeCompare(b.title));
}

export function whatItMeans(entity: Entity): string {
  if (entity.relation === "breach-title") {
    return "A public breach index lists this name. The row is the breach title and, when published, the data categories. It is not a copy of the stolen records.";
  }
  if (entity.relation === "mail-gap") return "A mail record that receivers expect is missing or weak. Spoofed mail is easier while it stays that way.";
  if (entity.relation === "header-gap") return "The homepage response is missing a header that browsers use to limit a class of attacks.";
  if (entity.relation === "listed-cve" || entity.type === "cve") {
    return "A public host index associates this address with a CVE. That is a lead, not proof the service is still vulnerable.";
  }
  if (entity.relation === "malware-association" || entity.relation === "malware-sample") {
    return "A public threat feed has associated this host with malware. Confirm it against the same feed before you treat the host as compromised.";
  }
  if (entity.relation === "published-phone" || entity.relation === "published-address" || entity.relation === "published-email") {
    return "This contact was published in a domain registration record, not scraped from a people-search site.";
  }
  if (entity.relation === "profile") return "A public profile API returned this account for the name you scanned.";
  if (entity.type === "subdomain" || entity.relation === "name-on-cert") return "This name appears on a public certificate or in an archive. It may be a live host or a retired one.";
  return `Observed via ${entity.source}. ${entity.relation.replaceAll("-", " ")}.`;
}

export function howToFix(entity: Entity): string {
  if (entity.relation === "blocklist") {
    return "A public malware-URL list names this host. Check the listing, take the site offline if it is yours, and request removal from that list after it is clean.";
  }
  if (entity.relation === "cookie-gap") {
    return "Set Secure and HttpOnly on that cookie, and SameSite where the browser should not send it on cross-site requests.";
  }
  if (entity.title.includes("SPF") || entity.value.startsWith("spf-missing")) {
    return "Publish an SPF record that lists only the servers allowed to send for this domain. Move to a hard fail after you have watched a week of mail.";
  }
  if (entity.title.includes("DMARC") || entity.value.startsWith("dmarc-missing")) {
    return "Publish a DMARC record at p=none with a report address, read the reports, then move to quarantine or reject.";
  }
  if (entity.relation === "header-gap") {
    return "Add the missing header on the web server or the CDN, then load the homepage again and confirm the header is present.";
  }
  if (entity.relation === "listed-cve" || entity.type === "cve") {
    return "Compare the CVE to the software version you actually run. Patch or remove that service if it matches. Ignore it if the version is already fixed.";
  }
  if (entity.relation === "listed-port") {
    return "Confirm the port is meant to be public. Close it at the host firewall if it is not.";
  }
  if (entity.relation === "malware-association" || entity.relation === "malware-sample") {
    return "Check the host on the feed named in the source. If the hit is current, clean or rebuild the host and rotate credentials that touched it.";
  }
  if (entity.relation === "breach-title") {
    return "Change any password that was reused from the time of that breach and turn on a second factor. This scan does not show password values. Use Footprint if a people-search page also lists you.";
  }
  if (entity.relation === "published-email" || entity.relation === "published-phone" || entity.relation === "published-address") {
    return "Turn on privacy at the registrar, or file that registry’s redaction form if the contact is a person rather than a role mailbox.";
  }
  if (entity.relation === "profile") {
    return "If the account is yours and should not be public, change the visibility on that site. If it is not yours, do not send a takedown for it.";
  }
  return "If you control this asset, change the setting and run the scan again. If someone else published it, use the Footprint tab and the broker’s own form.";
}
