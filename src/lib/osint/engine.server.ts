/**
 * Passive lookups against public sources, plus one authorized surface review.
 *
 * Adding a module:
 * 1. Register it in `catalog.ts`.
 * 2. Add a branch in `runModule` below.
 * 3. Return structured entities. Do not shell out to scanners.
 * 4. Do not add port scans, path brute force, exploit templates,
 *    credential stuffing, or password-reset oracles.
 */
import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";

import { moduleDef } from "@/lib/osint/catalog";
import { assertTarget, hostFrom, isPrivateIp, isPublicHost, normalizeTarget } from "@/lib/osint/guard";
import type { EntityDraft, Kind, ModuleResult, RunInput } from "@/lib/osint/types";

const UA = "FootprintOSINT/1.0 (passive public-source lookup)";

const hits: number[] = [];

function rateOk() {
  const now = Date.now();
  while (hits.length && now - hits[0]! > 60_000) hits.shift();
  if (hits.length >= 48) return false;
  hits.push(now);
  return true;
}

type Got = { status: number; text: string; headers: Headers; url: string; hops?: number };

async function getText(
  url: string,
  opts?: { headers?: Record<string, string>; timeout?: number; max?: number; redirect?: RequestRedirect },
): Promise<Got> {
  const res = await fetch(url, {
    redirect: opts?.redirect ?? "follow",
    headers: {
      "user-agent": UA,
      accept: "application/json,text/plain,text/html,*/*",
      ...(opts?.headers ?? {}),
    },
    signal: AbortSignal.timeout(opts?.timeout ?? 12_000),
  });
  const max = opts?.max ?? 1_600_000;
  const text = await res.text();
  if (text.length > max) {
    return { status: res.status, text: text.slice(0, max), headers: res.headers, url: res.url };
  }
  return { status: res.status, text, headers: res.headers, url: res.url };
}

async function assertResolvesPublic(hostname: string) {
  if (!isPublicHost(hostname)) throw new Error("That host is not a public target.");
  if (isPrivateIp(hostname)) throw new Error("Refusing a non-public address.");
  const records = await lookup(hostname, { all: true, verbatim: true });
  if (!records.length) throw new Error("Could not resolve host.");
  for (const rec of records) {
    if (isPrivateIp(rec.address)) throw new Error("Refusing a non-public address.");
  }
}

function draft(
  partial: EntityDraft,
): EntityDraft {
  return partial;
}

function dedupe(list: EntityDraft[]): EntityDraft[] {
  const seen = new Set<string>();
  const out: EntityDraft[] = [];
  for (const e of list) {
    const key = `${e.type}:${e.value.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(e);
  }
  return out;
}

function finish(
  module: string,
  started: number,
  entities: EntityDraft[],
  log: string[],
  extra?: { ok?: boolean; error?: string; truncated?: boolean },
): ModuleResult {
    const all = dedupe(entities);
    const truncated = Boolean(extra?.truncated) || all.length > 180;
    return {
      module,
      ok: extra?.ok ?? true,
      truncated,
      error: extra?.error,
      durationMs: Date.now() - started,
      entities: all.slice(0, 180),
      log,
    };
}

function fail(module: string, started: number, error: unknown, log: string[] = []): ModuleResult {
  const message = error instanceof Error ? error.message : "Lookup failed";
  return finish(module, started, [], [...log, message], { ok: false, error: message });
}

function belongs(name: string, domain: string) {
  const n = name.toLowerCase().replace(/\.$/, "").replace(/^\*\./, "");
  return n === domain || n.endsWith(`.${domain}`);
}

async function modCt(domain: string): Promise<ModuleResult> {
  const started = Date.now();
  const log: string[] = [];
  const names = new Set<string>();
  let truncated = false;
  try {
    const spotter = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`;
    const res = await getText(spotter, { timeout: 14_000 });
    if (res.status === 200) {
      const rows = JSON.parse(res.text) as { dns_names?: string[] }[];
      for (const row of rows) {
        for (const raw of row.dns_names ?? []) {
          for (const piece of raw.split(/\s+/)) {
            const name = piece.trim().toLowerCase().replace(/\.$/, "");
            if (!name || name.includes("*") || !belongs(name, domain)) continue;
            if (name === domain) continue;
            names.add(name);
          }
        }
      }
      log.push(`Cert Spotter returned ${rows.length} issuances, ${names.size} names under ${domain}.`);
    } else {
      log.push(`Cert Spotter HTTP ${res.status}. Trying crt.sh.`);
      const crt = await getText(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`, { timeout: 14_000 });
      if (crt.status !== 200) throw new Error(`Certificate search HTTP ${crt.status}`);
      const rows = JSON.parse(crt.text) as { name_value?: string }[];
      for (const row of rows) {
        for (const piece of (row.name_value ?? "").split(/\n/)) {
          const name = piece.trim().toLowerCase().replace(/\.$/, "");
          if (!name || name.includes("*") || !belongs(name, domain) || name === domain) continue;
          names.add(name);
        }
      }
      log.push(`crt.sh yielded ${names.size} names.`);
    }
  } catch (error) {
    return fail("ct", started, error, log);
  }
  const all = [...names].sort();
  const capped = all.slice(0, 150);
  if (all.length > capped.length) {
    truncated = true;
    log.push(`Keeping ${capped.length} of ${all.length} names.`);
  }
  const entities = capped.map((name) =>
    draft({
      type: "subdomain",
      value: name,
      severity: "info",
      relation: "name-on-cert",
      source: "ct",
      title: name,
      meta: { host: domain },
    }),
  );
  return finish("ct", started, entities, log, { truncated });
}

function vcardName(entity: unknown): string {
  return vcardFields(entity).name;
}

function isRedacted(value: string): boolean {
  return /redact|privacy|withheld|gdpr|not disclosed|data protected|whoisguard|contact privacy|domains by proxy/i.test(value);
}

function vcardFields(entity: unknown): { name: string; emails: string[]; phones: string[]; addresses: string[] } {
  const out = { name: "", emails: [] as string[], phones: [] as string[], addresses: [] as string[] };
  if (!entity || typeof entity !== "object") return out;
  const rows = (entity as { vcardArray?: unknown[] }).vcardArray?.[1];
  if (!Array.isArray(rows)) return out;
  for (const row of rows) {
    if (!Array.isArray(row) || row.length < 4) continue;
    const kind = String(row[0]);
    const value = row[3];
    if (kind === "fn" && typeof value === "string") out.name = value;
    if (kind === "email" && typeof value === "string") out.emails.push(value.trim());
    if (kind === "tel" && typeof value === "string") out.phones.push(value.trim());
    if (kind === "adr" && Array.isArray(value)) {
      const parts = value.map((part) => (typeof part === "string" ? part.trim() : "")).filter(Boolean);
      if (parts.length) out.addresses.push(parts.join(", "));
    }
  }
  return out;
}

async function modRdap(kind: Kind, target: string, domain: string): Promise<ModuleResult> {
  const started = Date.now();
  try {
    const url = kind === "ip" ? `https://rdap.org/ip/${encodeURIComponent(target)}` : `https://rdap.org/domain/${encodeURIComponent(domain)}`;
    const res = await getText(url, { timeout: 14_000 });
    if (res.status >= 400) throw new Error(`RDAP HTTP ${res.status}`);
    const data = JSON.parse(res.text) as {
      ldhName?: string;
      name?: string;
      handle?: string;
      status?: string[];
      startAddress?: string;
      endAddress?: string;
      nameservers?: { ldhName?: string }[];
      events?: { eventAction?: string; eventDate?: string }[];
      entities?: { roles?: string[] }[];
    };
    const entities: EntityDraft[] = [];
    const log: string[] = [];
    const registrar = (data.entities ?? []).find((e) => e.roles?.includes("registrar"));
    const registrarName = vcardName(registrar);
    const events = Object.fromEntries((data.events ?? []).map((e) => [e.eventAction ?? "", (e.eventDate ?? "").slice(0, 10)]));
    if (kind === "ip") {
      const label = data.name || data.handle || target;
      entities.push(
        draft({
          type: "asn",
          value: label,
          severity: "info",
          relation: "allocation",
          source: "rdap",
          title: label,
          meta: {
            handle: data.handle ?? "",
            start: data.startAddress ?? "",
            end: data.endAddress ?? "",
            status: (data.status ?? []).join(", "),
          },
        }),
      );
      log.push(`Network ${label} ${data.startAddress ?? ""}–${data.endAddress ?? ""}.`);
    } else {
      if (registrarName) {
        entities.push(
          draft({
            type: "finding",
            value: `registrar:${domain}`,
            severity: "info",
            relation: "registered-via",
            source: "rdap",
            title: `Registrar ${registrarName}`,
            meta: { registrar: registrarName, status: (data.status ?? []).join(", "), ...events },
          }),
        );
      }
      for (const ns of data.nameservers ?? []) {
        if (!ns.ldhName) continue;
        entities.push(
          draft({
            type: "domain",
            value: ns.ldhName.toLowerCase(),
            severity: "info",
            relation: "nameserver",
            source: "rdap",
            title: ns.ldhName.toLowerCase(),
          }),
        );
      }
      let emails = 0;
      let phones = 0;
      let addresses = 0;
      for (const contact of data.entities ?? []) {
        const role = contact.roles?.filter((item) => item !== "registrar").join(", ") || "contact";
        const card = vcardFields(contact);
        for (const email of card.emails) {
          if (emails >= 6 || isRedacted(email) || !looksEmail(email)) continue;
          emails += 1;
          entities.push(
            draft({
              type: "email",
              value: email.toLowerCase(),
              severity: "info",
              relation: "published-email",
              source: "rdap",
              title: email.toLowerCase(),
              meta: { role, host: domain },
            }),
          );
        }
        for (const phone of card.phones) {
          if (phones >= 6 || phone.length < 7 || isRedacted(phone)) continue;
          phones += 1;
          entities.push(
            draft({
              type: "finding",
              value: `phone:${phone}`,
              severity: "low",
              relation: "published-phone",
              source: "rdap",
              title: phone,
              meta: { phone, role, host: domain, note: "Published in registration data. Redacted fields are not recovered." },
            }),
          );
        }
        for (const address of card.addresses) {
          if (addresses >= 4 || isRedacted(address)) continue;
          addresses += 1;
          entities.push(
            draft({
              type: "finding",
              value: `address:${address.slice(0, 240)}`,
              severity: "low",
              relation: "published-address",
              source: "rdap",
              title: address.slice(0, 160),
              meta: { address: address.slice(0, 240), role, host: domain, note: "Published in registration data. Redacted fields are not recovered." },
            }),
          );
        }
      }
      log.push(
        `RDAP ${data.ldhName || domain}: registrar ${registrarName || "unknown"}, ${(data.nameservers ?? []).length} nameservers, published contacts ${emails} email / ${phones} phone / ${addresses} address.`,
      );
    }
    return finish("rdap", started, entities, log);
  } catch (error) {
    return fail("rdap", started, error);
  }
}

type DohAnswer = { type?: number; data?: string };

async function doh(name: string, type: string): Promise<DohAnswer[]> {
  const res = await getText(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`, {
    headers: { accept: "application/dns-json" },
    timeout: 8_000,
  });
  if (res.status !== 200) throw new Error(`DNS HTTP ${res.status}`);
  const data = JSON.parse(res.text) as { Status?: number; Answer?: DohAnswer[] };
  if (data.Status === 3) return [];
  return data.Answer ?? [];
}

function ptrName(ip: string): string {
  if (ip.includes(":")) {
    const full = expandV6(ip);
    return `${full.split(":").join("").split("").reverse().join(".")}.ip6.arpa`;
  }
  return `${ip.split(".").reverse().join(".")}.in-addr.arpa`;
}

function expandV6(ip: string): string {
  const [head, tail] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const missing = 8 - (h.length + t.length);
  const parts = [...h, ...Array.from({ length: Math.max(missing, 0) }, () => "0"), ...t];
  return parts.map((p) => p.padStart(4, "0")).join(":");
}

async function modDns(kind: Kind, target: string, domain: string): Promise<ModuleResult> {
  const started = Date.now();
  const entities: EntityDraft[] = [];
  const log: string[] = [];
  try {
    if (kind === "ip") {
      const answers = await doh(ptrName(target), "PTR");
      for (const a of answers) {
        const host = (a.data ?? "").replace(/\.$/, "").toLowerCase();
        if (!host) continue;
        entities.push(draft({ type: "domain", value: host, severity: "info", relation: "ptr", source: "dns", title: host, meta: { host: target } }));
      }
      log.push(entities.length ? `PTR ${entities.map((e) => e.value).join(", ")}` : "No PTR published.");
      return finish("dns", started, entities, log);
    }
    const types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];
    for (const type of types) {
      const answers = await doh(domain, type);
      for (const a of answers) {
        const data = (a.data ?? "").replace(/^"|"$/g, "").trim();
        if (!data) continue;
        if (type === "A" || type === "AAAA") {
          if (isPrivateIp(data)) continue;
          entities.push(draft({ type: "ip", value: data, severity: "info", relation: "resolves", source: "dns", title: `${type} ${data}`, meta: { record: type } }));
        } else if (type === "MX" || type === "NS" || type === "CNAME") {
          const host = data.split(" ").pop()?.replace(/\.$/, "").toLowerCase() ?? "";
          if (!host) continue;
          entities.push(draft({ type: "domain", value: host, severity: "info", relation: type.toLowerCase(), source: "dns", title: `${type} ${host}`, meta: { record: type } }));
        } else if (type === "TXT") {
          entities.push(
            draft({
              type: "finding",
              value: `txt:${domain}:${data.slice(0, 180)}`,
              severity: "info",
              relation: "txt",
              source: "dns",
              title: data.slice(0, 140),
              meta: { record: "TXT" },
            }),
          );
        } else {
          log.push(`SOA ${data.slice(0, 160)}`);
        }
      }
      log.push(`${type}: ${answers.length}`);
    }
    return finish("dns", started, entities, log);
  } catch (error) {
    return fail("dns", started, error, log);
  }
}

async function resolvePublicA(domain: string): Promise<string[]> {
  const answers = await doh(domain, "A");
  return answers.map((a) => a.data ?? "").filter((ip) => ip && !isPrivateIp(ip)).slice(0, 3);
}

async function modInternetDb(kind: Kind, target: string, domain: string): Promise<ModuleResult> {
  const started = Date.now();
  const log: string[] = [];
  try {
    const ips = kind === "ip" ? [target] : await resolvePublicA(domain);
    if (!ips.length) {
      log.push("No public A record to ask InternetDB about.");
      return finish("internetdb", started, [], log);
    }
    const entities: EntityDraft[] = [];
    for (const ip of ips) {
      const res = await getText(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, { timeout: 10_000 });
      if (res.status === 404) {
        log.push(`${ip}: InternetDB has no record.`);
        continue;
      }
      if (res.status !== 200) {
        log.push(`${ip}: HTTP ${res.status}`);
        continue;
      }
      const data = JSON.parse(res.text) as {
        ports?: number[];
        hostnames?: string[];
        vulns?: string[];
        tags?: string[];
        cpes?: string[];
      };
      entities.push(
        draft({
          type: "ip",
          value: ip,
          severity: "info",
          relation: "resolves",
          source: "internetdb",
          title: ip,
        }),
      );
      log.push(`${ip}: ports ${(data.ports ?? []).join(", ") || "none"}, vulns ${(data.vulns ?? []).length}.`);
      for (const port of (data.ports ?? []).slice(0, 20)) {
        entities.push(
          draft({
            type: "port",
            value: `${ip}:${port}`,
            severity: "info",
            relation: "listed-port",
            source: "internetdb",
            title: `${ip} tcp/${port}`,
            meta: { ip, port: String(port), linkTo: ip, linkRel: "on-address" },
          }),
        );
      }
      for (const host of (data.hostnames ?? []).slice(0, 12)) {
        entities.push(
          draft({
            type: host.endsWith(domain) && host !== domain ? "subdomain" : "domain",
            value: host.toLowerCase(),
            severity: "info",
            relation: "internetdb-hostname",
            source: "internetdb",
            title: host.toLowerCase(),
            meta: { ip },
          }),
        );
      }
      for (const cve of (data.vulns ?? []).slice(0, 20)) {
        entities.push(
          draft({
            type: "cve",
            value: `${cve} @ ${ip}`,
            severity: "high",
            relation: "listed-cve",
            source: "internetdb",
            title: `${cve} listed for ${ip}`,
            meta: {
              ip,
              cve,
              note: "InternetDB association. Not confirmation the host is exploitable.",
              linkTo: ip,
              linkRel: "listed-on",
            },
          }),
        );
      }
      if (data.tags?.length) log.push(`Tags: ${data.tags.join(", ")}`);
      if (data.cpes?.length) log.push(`CPE: ${data.cpes.slice(0, 6).join(", ")}`);
    }
    return finish("internetdb", started, entities, log);
  } catch (error) {
    return fail("internetdb", started, error, log);
  }
}

async function modWayback(domain: string): Promise<ModuleResult> {
  const started = Date.now();
  try {
    const url =
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}` +
      `&output=json&fl=original,timestamp,statuscode,mimetype&filter=statuscode:200&collapse=urlkey&limit=15`;
    const res = await getText(url, { timeout: 12_000 });
    if (res.status !== 200) throw new Error(`Wayback HTTP ${res.status}`);
    const rows = JSON.parse(res.text) as string[][];
    const body = rows.slice(1);
    const entities: EntityDraft[] = [];
    const hosts = new Set<string>();
    for (const row of body) {
      const [original, timestamp, status, mime] = row;
      if (!original) continue;
      let host = "";
      try {
        host = new URL(original).hostname.toLowerCase();
      } catch {
        continue;
      }
      if (belongs(host, domain) && host !== domain) hosts.add(host);
      entities.push(
        draft({
          type: "url",
          value: original.slice(0, 300),
          severity: "info",
          relation: "archived",
          source: "wayback",
          title: `${timestamp?.slice(0, 8) ?? ""} ${original}`.trim(),
          meta: { timestamp: timestamp ?? "", status: status ?? "", mime: mime ?? "", host },
        }),
      );
    }
    for (const host of hosts) {
      entities.push(draft({ type: "subdomain", value: host, severity: "info", relation: "seen-in-archive", source: "wayback", title: host }));
    }
    return finish("wayback", started, entities, [`${body.length} archived URLs.`]);
  } catch (error) {
    return fail("wayback", started, error);
  }
}

async function modOtx(domain: string): Promise<ModuleResult> {
  const started = Date.now();
  try {
    const res = await getText(
      `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/url_list?limit=20`,
      { timeout: 12_000 },
    );
    if (res.status === 429) throw new Error("OTX rate limit. Try again later.");
    if (res.status !== 200) throw new Error(`OTX HTTP ${res.status}`);
    const data = JSON.parse(res.text) as { url_list?: { url?: string; date?: string; hostname?: string }[] };
    const entities: EntityDraft[] = [];
    for (const row of (data.url_list ?? []).slice(0, 20)) {
      if (!row.url) continue;
      let host = (row.hostname ?? "").toLowerCase();
      try {
        host = host || new URL(row.url).hostname.toLowerCase();
      } catch {
        continue;
      }
      if (!belongs(host, domain)) continue;
      entities.push(
        draft({
          type: "url",
          value: row.url.slice(0, 300),
          severity: "info",
          relation: "otx-url",
          source: "otx",
          title: row.hostname || row.url,
          meta: { date: row.date ?? "", host: (row.hostname ?? "").toLowerCase() },
        }),
      );
    }
    return finish("otx", started, entities, [`${entities.length} OTX URLs.`]);
  } catch (error) {
    return fail("otx", started, error);
  }
}

async function modUrlscan(domain: string): Promise<ModuleResult> {
  const started = Date.now();
  try {
    const res = await getText(
      `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(`domain:${domain}`)}&size=15`,
      { timeout: 12_000 },
    );
    if (res.status === 429) throw new Error("urlscan rate limit.");
    if (res.status !== 200) throw new Error(`urlscan HTTP ${res.status}`);
    const data = JSON.parse(res.text) as {
      results?: { page?: { url?: string; title?: string; server?: string }; task?: { time?: string; url?: string } }[];
    };
    const entities: EntityDraft[] = [];
    for (const row of (data.results ?? []).slice(0, 15)) {
      const page = row.page?.url || row.task?.url;
      if (!page) continue;
      let host = "";
      try {
        host = new URL(page).hostname.toLowerCase();
      } catch {
        host = "";
      }
      if (!host || !belongs(host, domain)) continue;
      entities.push(
        draft({
          type: "url",
          value: page.slice(0, 300),
          severity: "info",
          relation: "urlscan",
          source: "urlscan",
          title: row.page?.title || page,
          meta: { time: row.task?.time ?? "", server: row.page?.server ?? "", host },
        }),
      );
      if (row.page?.server) {
        entities.push(
          draft({
            type: "tech",
            value: `${row.page.server} @ ${host || domain}`,
            severity: "info",
            relation: "fingerprint",
            source: "urlscan",
            title: row.page.server,
            meta: { host: host || domain },
          }),
        );
      }
    }
    return finish("urlscan", started, entities, [`${(data.results ?? []).length} public urlscan results.`]);
  } catch (error) {
    return fail("urlscan", started, error);
  }
}

async function modReputation(kind: Kind, target: string, domain: string, vtKey: string): Promise<ModuleResult> {
  const started = Date.now();
  if (!vtKey.trim()) {
    return finish("reputation", started, [], ["Skipped. Add a VirusTotal key in Settings to enable this."]);
  }
  try {
    const id = kind === "ip" ? `ip_addresses/${encodeURIComponent(target)}` : `domains/${encodeURIComponent(domain)}`;
    const res = await getText(`https://www.virustotal.com/api/v3/${id}`, {
      headers: { "x-apikey": vtKey.trim(), accept: "application/json" },
      timeout: 12_000,
    });
    if (res.status === 401 || res.status === 403) throw new Error("VirusTotal rejected the key.");
    if (res.status === 404) return finish("reputation", started, [], ["VirusTotal has no record."]);
    if (res.status !== 200) throw new Error(`VirusTotal HTTP ${res.status}`);
    const data = JSON.parse(res.text) as {
      data?: { attributes?: { last_analysis_stats?: Record<string, number>; reputation?: number; categories?: Record<string, string> } };
    };
    const stats = data.data?.attributes?.last_analysis_stats ?? {};
    const malicious = Number(stats.malicious ?? 0);
    const suspicious = Number(stats.suspicious ?? 0);
    const severity = malicious > 0 ? "high" : suspicious > 0 ? "medium" : "info";
    const categories = Object.values(data.data?.attributes?.categories ?? {}).slice(0, 4).join(", ");
    const entities = [
      draft({
        type: "finding",
        value: `vt:${kind === "ip" ? target : domain}`,
        severity,
        relation: "reputation",
        source: "virustotal",
        title: `VirusTotal malicious ${malicious}, suspicious ${suspicious}`,
        meta: {
          malicious: String(malicious),
          suspicious: String(suspicious),
          harmless: String(stats.harmless ?? 0),
          reputation: String(data.data?.attributes?.reputation ?? ""),
          categories,
        },
      }),
    ];
    return finish("reputation", started, entities, [`Engines: malicious ${malicious}, suspicious ${suspicious}.`]);
  } catch (error) {
    return fail("reputation", started, error);
  }
}

type ProfileHit = { site: string; url: string; title: string; meta?: Record<string, string> };

async function modProfiles(username: string): Promise<ModuleResult> {
  const started = Date.now();
  const log: string[] = [];
  let errors = 0;
  let misses = 0;
  const hitsFound: ProfileHit[] = [];

  async function grab(url: string, timeout = 8_000): Promise<Got | null> {
    try {
      return await getText(url, { timeout, headers: { accept: "application/json" } });
    } catch {
      errors += 1;
      return null;
    }
  }

  const jobs: (() => Promise<void>)[] = [
    async () => {
      const res = await grab(`https://api.github.com/users/${encodeURIComponent(username)}`);
      if (!res) return;
      if (res.status === 404) { misses += 1; return; }
      if (res.status !== 200) { errors += 1; log.push(`GitHub HTTP ${res.status}`); return; }
      const u = JSON.parse(res.text) as {
        html_url?: string;
        name?: string;
        bio?: string;
        public_repos?: number;
        blog?: string;
        avatar_url?: string;
        location?: string;
        company?: string;
        twitter_username?: string;
      };
      hitsFound.push({
        site: "GitHub",
        url: u.html_url || `https://github.com/${username}`,
        title: u.name || username,
        meta: {
          bio: (u.bio ?? "").slice(0, 180),
          repos: String(u.public_repos ?? ""),
          blog: u.blog ?? "",
          ...(u.avatar_url ? { photo: u.avatar_url } : {}),
          ...(u.location ? { location: u.location.slice(0, 120) } : {}),
          ...(u.company ? { company: u.company.slice(0, 120) } : {}),
          ...(u.twitter_username ? { twitter: u.twitter_username } : {}),
        },
      });
    },
    async () => {
      const res = await grab(`https://gitlab.com/api/v4/users?username=${encodeURIComponent(username)}`);
      if (!res || res.status !== 200) { errors += 1; return; }
      const rows = JSON.parse(res.text) as { username?: string; web_url?: string; name?: string; avatar_url?: string }[];
      const row = rows.find((r) => r.username?.toLowerCase() === username.toLowerCase());
      if (!row) { misses += 1; return; }
      hitsFound.push({
        site: "GitLab",
        url: row.web_url || `https://gitlab.com/${username}`,
        title: row.name || username,
        meta: row.avatar_url ? { photo: row.avatar_url } : undefined,
      });
    },
    async () => {
      const res = await grab(`https://codeberg.org/api/v1/users/${encodeURIComponent(username)}`);
      if (!res) return;
      if (res.status === 404) { misses += 1; return; }
      if (res.status !== 200) { errors += 1; return; }
      const u = JSON.parse(res.text) as { html_url?: string; full_name?: string; avatar_url?: string };
      hitsFound.push({
        site: "Codeberg",
        url: u.html_url || `https://codeberg.org/${username}`,
        title: u.full_name || username,
        meta: u.avatar_url ? { photo: u.avatar_url } : undefined,
      });
    },
    async () => {
      const res = await grab(`https://hacker-news.firebaseio.com/v0/user/${encodeURIComponent(username)}.json`);
      if (!res || res.status !== 200) { errors += 1; return; }
      if (res.text.trim() === "null") { misses += 1; return; }
      const u = JSON.parse(res.text) as { id?: string; karma?: number; about?: string };
      if (!u?.id) { misses += 1; return; }
      hitsFound.push({
        site: "Hacker News",
        url: `https://news.ycombinator.com/user?id=${encodeURIComponent(u.id)}`,
        title: u.id,
        meta: { karma: String(u.karma ?? ""), about: (u.about ?? "").replace(/<[^>]+>/g, "").slice(0, 160) },
      });
    },
    async () => {
      const res = await grab(`https://dev.to/api/users/by_username?url=${encodeURIComponent(username)}`);
      if (!res) return;
      if (res.status === 404) { misses += 1; return; }
      if (res.status !== 200) { errors += 1; return; }
      const u = JSON.parse(res.text) as { name?: string; summary?: string; github_username?: string; twitter_username?: string };
      hitsFound.push({
        site: "DEV",
        url: `https://dev.to/${username}`,
        title: u.name || username,
        meta: {
          summary: (u.summary ?? "").slice(0, 160),
          ...(u.github_username ? { linkTo: u.github_username, linkRel: "also-known-as" } : {}),
          github: u.github_username ?? "",
          twitter: u.twitter_username ?? "",
        },
      });
      if (u.github_username && u.github_username.toLowerCase() !== username.toLowerCase()) {
        hitsFound.push({
          site: "GitHub (linked)",
          url: `https://github.com/${u.github_username}`,
          title: u.github_username,
          meta: { linkedUsername: u.github_username },
        });
      }
    },
    async () => {
      const res = await grab(`https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(`${username}.bsky.social`)}`);
      if (!res) return;
      if (res.status === 400 || res.status === 404) { misses += 1; return; }
      if (res.status !== 200) { errors += 1; return; }
      const u = JSON.parse(res.text) as { handle?: string; displayName?: string; description?: string };
      hitsFound.push({
        site: "Bluesky",
        url: `https://bsky.app/profile/${u.handle || `${username}.bsky.social`}`,
        title: u.displayName || u.handle || username,
        meta: { about: (u.description ?? "").slice(0, 160) },
      });
    },
    async () => {
      const res = await grab(`https://mastodon.social/api/v1/accounts/lookup?acct=${encodeURIComponent(username)}`);
      if (!res) return;
      if (res.status === 404) { misses += 1; return; }
      if (res.status !== 200) { errors += 1; return; }
      const u = JSON.parse(res.text) as { url?: string; display_name?: string; note?: string; avatar?: string };
      hitsFound.push({
        site: "Mastodon",
        url: u.url || `https://mastodon.social/@${username}`,
        title: u.display_name || username,
        meta: {
          about: (u.note ?? "").replace(/<[^>]+>/g, "").slice(0, 160),
          ...(u.avatar ? { photo: u.avatar } : {}),
        },
      });
    },
    async () => {
      const res = await grab(`https://huggingface.co/api/users/${encodeURIComponent(username)}/overview`);
      if (!res) return;
      if (res.status === 404) { misses += 1; return; }
      if (res.status !== 200) { errors += 1; return; }
      const u = JSON.parse(res.text) as { fullname?: string; numModels?: number };
      hitsFound.push({
        site: "Hugging Face",
        url: `https://huggingface.co/${username}`,
        title: u.fullname || username,
        meta: { models: String(u.numModels ?? "") },
      });
    },
    async () => {
      const res = await grab(`https://hub.docker.com/v2/users/${encodeURIComponent(username)}`);
      if (!res) return;
      if (res.status === 404) { misses += 1; return; }
      if (res.status !== 200) { errors += 1; return; }
      const u = JSON.parse(res.text) as { full_name?: string; location?: string };
      hitsFound.push({
        site: "Docker Hub",
        url: `https://hub.docker.com/u/${username}`,
        title: u.full_name || username,
        meta: { location: u.location ?? "" },
      });
    },
    async () => {
      const res = await grab(`https://keybase.io/_/api/1.0/user/lookup.json?usernames=${encodeURIComponent(username)}`);
      if (!res || res.status !== 200) { errors += 1; return; }
      const data = JSON.parse(res.text) as { them?: { basics?: { username?: string }; pictures?: { primary?: { url?: string } } }[] };
      const row = data.them?.find((t) => t.basics?.username?.toLowerCase() === username.toLowerCase());
      if (!row?.basics?.username) { misses += 1; return; }
      const photo = row.pictures?.primary?.url;
      hitsFound.push({
        site: "Keybase",
        url: `https://keybase.io/${row.basics.username}`,
        title: row.basics.username,
        meta: photo ? { photo } : undefined,
      });
    },
    async () => {
      const res = await grab(`https://api.modrinth.com/v2/user/${encodeURIComponent(username)}`);
      if (!res) return;
      if (res.status === 404) { misses += 1; return; }
      if (res.status !== 200) { errors += 1; return; }
      const u = JSON.parse(res.text) as { username?: string; name?: string };
      hitsFound.push({
        site: "Modrinth",
        url: `https://modrinth.com/user/${u.username || username}`,
        title: u.name || u.username || username,
      });
    },
  ];

  let cursor = 0;
  async function worker() {
    while (cursor < jobs.length) {
      const job = jobs[cursor];
      cursor += 1;
      if (job) await job();
    }
  }
  await Promise.all(Array.from({ length: 4 }, () => worker()));

  const entities: EntityDraft[] = [];
  for (const hit of hitsFound) {
    let host = "";
    try {
      host = new URL(hit.url).hostname;
    } catch {
      host = "";
    }
    entities.push(
      draft({
        type: "profile",
        value: hit.url,
        severity: "info",
        relation: "profile",
        source: "profiles",
        title: `${hit.site}: ${hit.title}`,
        meta: { site: hit.site, host, ...(hit.meta ?? {}) },
      }),
    );
    const linked = hit.meta?.linkedUsername;
    if (linked) {
      entities.push(
        draft({
          type: "username",
          value: linked,
          severity: "info",
          relation: "also-known-as",
          source: "profiles",
          title: linked,
          meta: { via: hit.site },
        }),
      );
    }
  }
  log.push(`Checked ${jobs.length} public APIs. ${hitsFound.length} hits, ${misses} confirmed misses, ${errors} errors or blocks.`);
  if (!hitsFound.length && errors === jobs.length) {
    return fail("profiles", started, new Error("Every profile source failed or blocked the lookup."), log);
  }
  return finish("profiles", started, entities, log);
}

async function modBreach(email: string, hibpKey: string): Promise<ModuleResult> {
  const started = Date.now();
  const entities: EntityDraft[] = [];
  const log: string[] = [];
  const domain = email.split("@")[1] ?? "";
  if (domain && isPublicHost(domain)) {
    entities.push(draft({ type: "domain", value: domain, severity: "info", relation: "email-domain", source: "breach", title: domain }));
  }
  try {
    const res = await getText(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`, { timeout: 12_000 });
    if (res.status === 200) {
      const data = JSON.parse(res.text) as { Error?: string; breaches?: unknown };
      if (data.Error) {
        log.push("XposedOrNot: no breach title for this address.");
      } else {
        const flat: string[] = [];
        const walk = (node: unknown) => {
          if (typeof node === "string") flat.push(node);
          else if (Array.isArray(node)) node.forEach(walk);
        };
        walk(data.breaches);
        const unique = [...new Set(flat.map((s) => s.trim()).filter(Boolean))].slice(0, 40);
        log.push(`XposedOrNot: ${unique.length} breach titles.`);
        for (const name of unique) {
          entities.push(
            draft({
              type: "breach",
              value: `${name} (${email})`,
              severity: "high",
              relation: "breach-title",
              source: "xposedornot",
              title: name,
              meta: { email, note: "Breach title only. No passwords or dumped records are retrieved." },
            }),
          );
        }
        if (unique.length > 40) log.push("Truncated breach titles at 40.");
      }
    } else {
      log.push(`XposedOrNot HTTP ${res.status}`);
    }
  } catch (error) {
    log.push(error instanceof Error ? error.message : "XposedOrNot failed");
  }

  const hash = createHash("md5").update(email.trim().toLowerCase()).digest("hex");
  try {
    const res = await getText(`https://www.gravatar.com/avatar/${hash}?d=404`, { timeout: 8_000, max: 200_000 });
    if (res.status === 200) {
      entities.push(
        draft({
          type: "profile",
          value: `https://gravatar.com/${hash}`,
          severity: "info",
          relation: "gravatar",
          source: "gravatar",
          title: "Gravatar image published",
          meta: { hash, photo: `https://www.gravatar.com/avatar/${hash}?s=128&d=404` },
        }),
      );
      log.push("Gravatar image exists.");
    } else {
      log.push("No Gravatar image.");
    }
  } catch {
    log.push("Gravatar lookup failed.");
  }

  if (hibpKey.trim()) {
    try {
      const res = await getText(
        `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
        { headers: { "hibp-api-key": hibpKey.trim(), "user-agent": UA }, timeout: 12_000 },
      );
      if (res.status === 404) log.push("HIBP: no breach for this address.");
      else if (res.status === 401) log.push("HIBP rejected the key.");
      else if (res.status !== 200) log.push(`HIBP HTTP ${res.status}`);
      else {
        const rows = JSON.parse(res.text) as { Name?: string; BreachDate?: string; DataClasses?: string[] }[];
        log.push(`HIBP: ${rows.length} breaches.`);
        for (const row of rows.slice(0, 30)) {
          if (!row.Name) continue;
          entities.push(
            draft({
              type: "breach",
              value: `HIBP ${row.Name} (${email})`,
              severity: "high",
              relation: "breach-title",
              source: "hibp",
              title: `${row.Name} (${row.BreachDate ?? "date unknown"})`,
              meta: {
                email,
                classes: (row.DataClasses ?? []).slice(0, 8).join(", "),
                note: "Categories only. Password material is not requested or stored.",
              },
            }),
          );
        }
      }
    } catch (error) {
      log.push(error instanceof Error ? `HIBP: ${error.message}` : "HIBP failed");
    }
  } else {
    log.push("HIBP skipped. Add a key in Settings for that source.");
  }

  const xposedFailed = log.some((l) => l.startsWith("XposedOrNot HTTP") || l.includes("XposedOrNot failed"));
  if (!entities.length && xposedFailed) return fail("breach", started, new Error("Breach sources failed."), log);
  return finish("breach", started, entities, log);
}

function stripTags(s: string) {
  return s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

async function safePage(url: string): Promise<Got> {
  const first = new URL(url);
  await assertResolvesPublic(first.hostname);
  let current = first;
  let hops = 0;
  for (let hop = 0; hop < 3; hop += 1) {
    const res = await fetch(current.toString(), {
      redirect: "manual",
      headers: { "user-agent": UA, accept: "text/html,application/json,text/plain,*/*" },
      signal: AbortSignal.timeout(10_000),
    });
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      await res.body?.cancel();
      if (!loc) throw new Error("Redirect with no location.");
      const next = new URL(loc, current);
      if (next.protocol !== "http:" && next.protocol !== "https:") throw new Error("Refusing non-http redirect.");
      if (next.port && next.port !== "80" && next.port !== "443") throw new Error("Refusing unusual port.");
      await assertResolvesPublic(next.hostname);
      current = next;
      hops += 1;
      continue;
    }
    const text = (await res.text()).slice(0, 120_000);
    return { status: res.status, text, headers: res.headers, url: current.toString(), hops };
  }
  throw new Error("Too many redirects.");
}

async function modSurface(kind: Kind, target: string, domain: string, authorized: boolean): Promise<ModuleResult> {
  const started = Date.now();
  if (!authorized) return fail("surface", started, new Error("Surface review stays off until you confirm authorization."));
  const pageUrl = kind === "url" ? target : `https://${domain}`;
  const log: string[] = ["Authorized surface review: homepage, robots.txt, security.txt, sitemap.xml."];
  try {
    await assertResolvesPublic(domain);
    const home = await safePage(pageUrl);
    const entities: EntityDraft[] = [];
    const titleMatch = home.text.match(/<title[^>]*>([^<]{1,180})<\/title>/i);
    const title = stripTags(titleMatch?.[1] ?? "").slice(0, 160);
    const gen = home.text.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i)?.[1] ?? "";
    const server = home.headers.get("server") ?? "";
    const powered = home.headers.get("x-powered-by") ?? "";
    entities.push(
      draft({
        type: "finding",
        value: `surface:${home.url}`,
        severity: "info",
        relation: "surface",
        source: "surface",
        title: title || `HTTP ${home.status}`,
        meta: { status: String(home.status), finalUrl: home.url, server, powered },
      }),
    );
    log.push(`Homepage HTTP ${home.status} ${title ? `“${title}”` : ""}`.trim());
    const hops = home.hops ?? 0;
    if (hops > 0) {
      entities.push(
        draft({
          type: "url",
          value: home.url,
          severity: "info",
          relation: "redirect",
          source: "surface",
          title: `Followed ${hops} redirect${hops === 1 ? "" : "s"}`,
          meta: { finalUrl: home.url },
        }),
      );
    }
    const cookies = typeof home.headers.getSetCookie === "function" ? home.headers.getSetCookie() : [];
    for (const raw of cookies.slice(0, 8)) {
      const name = raw.split("=")[0]?.trim().slice(0, 80) || "cookie";
      const flags = ["Secure", "HttpOnly", "SameSite"].filter((flag) => raw.toLowerCase().includes(flag.toLowerCase()));
      const weak = !/secure/i.test(raw) || !/httponly/i.test(raw);
      entities.push(
        draft({
          type: "tech",
          value: `cookie:${domain}:${name}`,
          severity: weak ? "low" : "info",
          relation: weak ? "cookie-gap" : "cookie",
          source: "surface",
          title: weak ? `Cookie ${name} missing a flag` : `Cookie ${name}`,
          meta: { flags: flags.join(", ") || "none", note: "Name and flags only. The cookie value is not stored." },
        }),
      );
    }
    const og = (prop: string) => {
      const a = new RegExp(`<meta[^>]+(?:property|name)=["']${prop}["'][^>]+content=["']([^"']+)`, "i");
      const b = new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["']${prop}["']`, "i");
      return stripTags(home.text.match(a)?.[1] ?? home.text.match(b)?.[1] ?? "").slice(0, 140);
    };
    for (const [prop, label] of [
      ["og:site_name", "Site name"],
      ["og:title", "Social title"],
    ] as const) {
      const value = og(prop);
      if (!value) continue;
      entities.push(
        draft({
          type: "tech",
          value: `${prop}:${domain}:${value}`,
          severity: "info",
          relation: "social-tag",
          source: "surface",
          title: `${label}: ${value}`,
        }),
      );
    }
    if (server) {
      entities.push(draft({ type: "tech", value: server, severity: "info", relation: "fingerprint", source: "surface", title: `Server ${server}` }));
    }
    if (powered) {
      entities.push(draft({ type: "tech", value: powered, severity: "info", relation: "fingerprint", source: "surface", title: `X-Powered-By ${powered}` }));
    }
    if (gen) {
      entities.push(draft({ type: "tech", value: gen.slice(0, 80), severity: "info", relation: "fingerprint", source: "surface", title: `Generator ${gen.slice(0, 80)}` }));
    }
    const wanted: [string, string][] = [
      ["strict-transport-security", "HSTS"],
      ["content-security-policy", "Content-Security-Policy"],
      ["x-content-type-options", "X-Content-Type-Options"],
      ["referrer-policy", "Referrer-Policy"],
      ["x-frame-options", "X-Frame-Options or frame protection"],
    ];
    for (const [header, label] of wanted) {
      const value = home.headers.get(header);
      if (!value) {
        entities.push(
          draft({
            type: "finding",
            value: `missing-header:${domain}:${header}`,
            severity: "low",
            relation: "header-gap",
            source: "surface",
            title: `${label} not observed`,
            meta: { header, note: "Observed absence on one response. Not an exploit." },
          }),
        );
      } else {
        log.push(`${label}: ${value.slice(0, 120)}`);
      }
    }
    const origin = new URL(home.url).origin;
    for (const path of ["/robots.txt", "/.well-known/security.txt", "/sitemap.xml"]) {
      try {
        const file = await safePage(`${origin}${path}`);
        if (file.status >= 200 && file.status < 300 && file.text.trim()) {
          entities.push(
            draft({
              type: "url",
              value: `${origin}${path}`,
              severity: "info",
              relation: "well-known",
              source: "surface",
              title: path,
              meta: { status: String(file.status), host: domain },
            }),
          );
          if (path === "/robots.txt") {
            const rules = file.text
              .split(/\r?\n/)
              .map((l) => l.trim())
              .filter((l) => /^disallow:/i.test(l))
              .slice(0, 12);
            if (rules.length) log.push(`robots.txt disallows: ${rules.join(" | ")}`);
          }
          if (path.endsWith("security.txt")) {
            const contact = file.text.split(/\r?\n/).find((l) => /^contact:/i.test(l));
            if (contact) log.push(contact.slice(0, 180));
          }
        } else {
          log.push(`${path} HTTP ${file.status}`);
        }
      } catch (error) {
        log.push(`${path}: ${error instanceof Error ? error.message : "failed"}`);
      }
    }
    return finish("surface", started, entities, log);
  } catch (error) {
    return fail("surface", started, error, log);
  }
}

const MAIL_PROVIDERS: [string, string][] = [
  ["protection.outlook.com", "Microsoft 365"],
  ["outlook.com", "Microsoft 365"],
  ["google.com", "Google"],
  ["googlemail.com", "Google"],
  ["pphosted.com", "Proofpoint"],
  ["ppe-hosted.com", "Proofpoint"],
  ["mimecast.com", "Mimecast"],
  ["barracudanetworks.com", "Barracuda"],
  ["zoho.com", "Zoho"],
  ["zoho.eu", "Zoho"],
  ["protonmail.ch", "Proton"],
  ["proton.me", "Proton"],
  ["yandex.net", "Yandex"],
  ["mail.ru", "Mail.ru"],
  ["secureserver.net", "GoDaddy"],
  ["emailsrvr.com", "Rackspace"],
  ["messagingengine.com", "Fastmail"],
  ["icloud.com", "Apple"],
  ["amazonaws.com", "Amazon SES"],
  ["sendgrid.net", "SendGrid"],
  ["mailgun.org", "Mailgun"],
  ["titan.email", "Titan"],
  ["privateemail.com", "Namecheap"],
  ["hostinger.com", "Hostinger"],
  ["cf-emailsecurity.net", "Cloudflare Email Security"],
  ["iphmx.com", "Cisco"],
  ["messagelabs.com", "Broadcom"],
  ["sophos.com", "Sophos"],
];

const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com",
  "guerrillamail.com",
  "guerrillamail.info",
  "guerrillamail.biz",
  "guerrillamail.de",
  "guerrillamail.net",
  "guerrillamail.org",
  "sharklasers.com",
  "grr.la",
  "yopmail.com",
  "tempmail.com",
  "temp-mail.org",
  "10minutemail.com",
  "throwawaymail.com",
  "getnada.com",
  "trashmail.com",
  "dispostable.com",
  "maildrop.cc",
  "fakemail.net",
  "mailnesia.com",
  "mohmal.com",
  "tempail.com",
  "emailondeck.com",
  "mintemail.com",
  "moakt.com",
  "spamgourmet.com",
  "discard.email",
  "dropmail.me",
  "fakeinbox.com",
  "spam4.me",
]);

const ROLE_LOCALS = new Set([
  "admin",
  "administrator",
  "postmaster",
  "hostmaster",
  "webmaster",
  "abuse",
  "noc",
  "security",
  "info",
  "sales",
  "support",
  "contact",
  "noreply",
  "no-reply",
  "office",
  "billing",
  "marketing",
  "privacy",
  "legal",
  "root",
]);

function unquoteTxt(data: string): string {
  return data.replace(/^"|"$/g, "").replace(/"\s+"/g, "").trim();
}

function dmarcTag(record: string, name: string): string {
  const match = record.match(new RegExp(`(?:^|;)\\s*${name}\\s*=\\s*([^;]+)`, "i"));
  return match?.[1]?.trim() ?? "";
}

function looksEmail(value: string): boolean {
  return /^[a-z0-9._%+-]{1,64}@[a-z0-9.-]+\.[a-z]{2,63}$/i.test(value);
}

function mailProvider(hosts: string[]): string {
  for (const host of hosts) {
    const hit = MAIL_PROVIDERS.find(([suffix]) => host === suffix || host.endsWith(`.${suffix}`));
    if (hit) return hit[1];
  }
  return "";
}

function seenDay(ms: number): string {
  if (!ms || ms < 1_000_000_000_000) return "";
  return new Date(ms).toISOString().slice(0, 10);
}

function cleanName(answer: string): string {
  const token = answer.trim().split(/\s+/).pop() ?? "";
  return token.replace(/\.$/, "").toLowerCase();
}

function hostEquals(raw: string, domain: string): boolean {
  const value = raw.trim();
  if (!value) return false;
  try {
    const url = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    return host === domain || host.endsWith(`.${domain}`);
  } catch {
    return false;
  }
}

async function modMail(kind: Kind, target: string, domain: string): Promise<ModuleResult> {
  const started = Date.now();
  const log: string[] = [];
  if (!domain || !isPublicHost(domain)) return fail("mail", started, new Error("That mail domain is not a public host."));
  const entities: EntityDraft[] = [];
  try {
    if (kind === "email") {
      entities.push(draft({ type: "domain", value: domain, severity: "info", relation: "email-domain", source: "mail", title: domain }));
      const local = target.split("@")[0]?.toLowerCase() ?? "";
      if (ROLE_LOCALS.has(local)) {
        entities.push(
          draft({
            type: "finding",
            value: `role:${target}`,
            severity: "info",
            relation: "role-mailbox",
            source: "mail",
            title: `Role mailbox (${local})`,
            meta: { email: target },
          }),
        );
      }
      if (DISPOSABLE_DOMAINS.has(domain)) {
        entities.push(
          draft({
            type: "finding",
            value: `disposable:${domain}`,
            severity: "low",
            relation: "disposable-domain",
            source: "mail",
            title: "Known disposable mail domain",
            meta: { domain },
          }),
        );
      }
    }

    const mxAnswers = await doh(domain, "MX");
    const mxHosts: string[] = [];
    for (const row of mxAnswers) {
      const host = cleanName(row.data ?? "");
      if (!host || host === domain || !host.includes(".")) continue;
      mxHosts.push(host);
      entities.push(
        draft({
          type: "domain",
          value: host,
          severity: "info",
          relation: "mx",
          source: "mail",
          title: `MX ${host}`,
          meta: { record: "MX", host: domain },
        }),
      );
    }
    if (!mxHosts.length) {
      entities.push(
        draft({
          type: "finding",
          value: `mx-missing:${domain}`,
          severity: "low",
          relation: "mail-gap",
          source: "mail",
          title: "No MX published",
          meta: { domain, note: "The domain may not receive mail, or it relies on an implicit A record." },
        }),
      );
      log.push("No MX.");
    } else {
      log.push(`MX: ${mxHosts.join(", ")}`);
      const provider = mailProvider(mxHosts);
      if (provider) {
        entities.push(
          draft({
            type: "tech",
            value: `${provider} mail @ ${domain}`,
            severity: "info",
            relation: "mail-provider",
            source: "mail",
            title: `Mail hosted at ${provider}`,
            meta: { provider, domain },
          }),
        );
      }
    }

    const txt = await doh(domain, "TXT");
    const spf = txt.map((row) => unquoteTxt(row.data ?? "")).find((row) => /^v=spf1\b/i.test(row));
    if (!spf) {
      entities.push(draft({ type: "finding", value: `spf-missing:${domain}`, severity: "low", relation: "mail-gap", source: "mail", title: "No SPF record", meta: { domain } }));
      log.push("No SPF.");
    } else {
      const qualifier = /\s([~?+-])all\b/i.exec(spf)?.[1] ?? "";
      const loose = qualifier === "+";
      const soft = qualifier === "~" || qualifier === "?";
      entities.push(
        draft({
          type: "finding",
          value: `spf:${domain}`,
          severity: loose ? "medium" : soft || !qualifier ? "low" : "info",
          relation: "spf",
          source: "mail",
          title: loose ? "SPF ends with +all" : qualifier ? `SPF ${qualifier}all` : "SPF present, no all mechanism",
          meta: { record: spf.slice(0, 240), domain },
        }),
      );
      log.push(`SPF ${qualifier || "no all"}`);
    }

    const dmarcRows = await doh(`_dmarc.${domain}`, "TXT");
    const dmarc = dmarcRows.map((row) => unquoteTxt(row.data ?? "")).find((row) => /^v=DMARC1\b/i.test(row));
    if (!dmarc) {
      entities.push(draft({ type: "finding", value: `dmarc-missing:${domain}`, severity: "low", relation: "mail-gap", source: "mail", title: "No DMARC record", meta: { domain } }));
      log.push("No DMARC.");
    } else {
      const policy = dmarcTag(dmarc, "p").toLowerCase();
      entities.push(
        draft({
          type: "finding",
          value: `dmarc:${domain}`,
          severity: policy === "reject" || policy === "quarantine" ? "info" : "low",
          relation: "dmarc",
          source: "mail",
          title: policy ? `DMARC p=${policy}` : "DMARC present",
          meta: { record: dmarc.slice(0, 240), policy, domain },
        }),
      );
      log.push(`DMARC p=${policy || "unset"}`);
      for (const raw of (dmarc.match(/mailto:([^,\s;]+)/gi) ?? []).slice(0, 4)) {
        const email = raw.slice("mailto:".length).toLowerCase();
        if (!looksEmail(email)) continue;
        if (kind === "email" && email === target.toLowerCase()) continue;
        entities.push(
          draft({
            type: "email",
            value: email,
            severity: "info",
            relation: "dmarc-report",
            source: "mail",
            title: email,
            meta: { via: "DMARC rua", host: domain },
          }),
        );
      }
    }

    const sts = await doh(`_mta-sts.${domain}`, "TXT");
    const stsTxt = sts.map((row) => unquoteTxt(row.data ?? "")).find((row) => /^v=STSv1\b/i.test(row));
    if (stsTxt) {
      entities.push(
        draft({
          type: "finding",
          value: `mta-sts:${domain}`,
          severity: "info",
          relation: "mta-sts",
          source: "mail",
          title: "MTA-STS published",
          meta: { record: stsTxt.slice(0, 160), domain },
        }),
      );
      log.push("MTA-STS published.");
    } else {
      log.push("No MTA-STS.");
    }

    const bimi = await doh(`default._bimi.${domain}`, "TXT");
    const bimiTxt = bimi.map((row) => unquoteTxt(row.data ?? "")).find((row) => /^v=BIMI1\b/i.test(row));
    if (bimiTxt) {
      entities.push(
        draft({
          type: "finding",
          value: `bimi:${domain}`,
          severity: "info",
          relation: "bimi",
          source: "mail",
          title: "BIMI record published",
          meta: { record: bimiTxt.slice(0, 180), domain },
        }),
      );
      log.push("BIMI published.");
    }

    const caa = await doh(domain, "CAA");
    const caaText = caa.map((row) => unquoteTxt(row.data ?? "")).filter(Boolean);
    const issuers = [
      ...new Set(
        caaText
          .map((record) => record.match(/\b(issue|issuewild|iodef)\s+"?([^"\s;]+)/i))
          .filter((match): match is RegExpMatchArray => Boolean(match?.[2]))
          .map((match) => `${match[1]!.toLowerCase()} ${match[2]}`),
      ),
    ].slice(0, 8);
    if (issuers.length) {
      entities.push(
        draft({
          type: "finding",
          value: `caa:${domain}`,
          severity: "info",
          relation: "caa",
          source: "mail",
          title: `CAA ${issuers.join(" · ").slice(0, 140)}`,
          meta: { records: issuers.join(" | "), domain },
        }),
      );
      log.push(`CAA: ${issuers.join(" | ")}`);
    }
    for (const raw of caaText.join(" ").match(/mailto:([^,\s;"]+)/gi)?.slice(0, 3) ?? []) {
      const email = raw.slice("mailto:".length).toLowerCase();
      if (!looksEmail(email)) continue;
      if (kind === "email" && email === target.toLowerCase()) continue;
      entities.push(
        draft({
          type: "email",
          value: email,
          severity: "info",
          relation: "caa-report",
          source: "mail",
          title: email,
          meta: { via: "CAA iodef", host: domain },
        }),
      );
    }

    if (kind === "email") {
      const hash = createHash("md5").update(target.trim().toLowerCase()).digest("hex");
      try {
        const res = await getText(`https://gravatar.com/${hash}.json`, { timeout: 8_000 });
        if (res.status === 200 && res.text.trim().startsWith("{")) {
          const data = JSON.parse(res.text) as {
            entry?: { displayName?: string; profileUrl?: string; aboutMe?: string; currentLocation?: string; accounts?: { shortname?: string; url?: string; username?: string }[] }[];
          };
          const entry = data.entry?.[0];
          if (entry) {
            entities.push(
              draft({
                type: "profile",
                value: entry.profileUrl || `https://gravatar.com/${hash}`,
                severity: "info",
                relation: "gravatar",
                source: "gravatar",
                title: entry.displayName ? `Gravatar ${entry.displayName}` : "Gravatar profile",
                meta: { about: (entry.aboutMe ?? "").slice(0, 160), location: entry.currentLocation ?? "", hash, photo: `https://www.gravatar.com/avatar/${hash}?s=128&d=404` },
              }),
            );
            log.push("Gravatar profile published.");
            for (const account of (entry.accounts ?? []).slice(0, 8)) {
              if (!account.url) continue;
              entities.push(
                draft({
                  type: "profile",
                  value: account.url,
                  severity: "info",
                  relation: "profile",
                  source: "gravatar",
                  title: `${account.shortname || "Account"}: ${account.username || account.url}`,
                  meta: { site: account.shortname ?? "", via: "gravatar" },
                }),
              );
              if (account.username && /^[a-zA-Z0-9][a-zA-Z0-9_-]{1,38}$/.test(account.username)) {
                entities.push(
                  draft({
                    type: "username",
                    value: account.username,
                    severity: "info",
                    relation: "also-known-as",
                    source: "gravatar",
                    title: account.username,
                    meta: { via: account.shortname || "gravatar" },
                  }),
                );
              }
            }
          }
        } else {
          log.push("No Gravatar profile.");
        }
      } catch {
        log.push("Gravatar lookup failed.");
      }
    }

    return finish("mail", started, entities, log);
  } catch (error) {
    return fail("mail", started, error, log);
  }
}

type RipeEnvelope<T> = { status?: string; data?: T };

async function ripeGet<T>(url: string): Promise<{ data: T | null; error: string }> {
  try {
    const res = await getText(url, { timeout: 8_000 });
    if (res.status !== 200) return { data: null, error: `HTTP ${res.status}` };
    const body = JSON.parse(res.text) as RipeEnvelope<T>;
    if (body.status && body.status !== "ok") return { data: null, error: body.status };
    return { data: body.data ?? null, error: "" };
  } catch (error) {
    return { data: null, error: error instanceof Error ? error.message : "failed" };
  }
}

async function modBgp(kind: Kind, target: string, domain: string): Promise<ModuleResult> {
  const started = Date.now();
  const log: string[] = [];
  try {
    const ips = kind === "ip" ? [target] : await resolvePublicA(domain);
    if (!ips.length) return finish("bgp", started, [], ["No public A record to look up."]);
    const entities: EntityDraft[] = [];
    let failures = 0;
    for (const ip of ips.slice(0, 2)) {
      if (kind !== "ip") {
        entities.push(draft({ type: "ip", value: ip, severity: "info", relation: "resolves", source: "ripe", title: ip, meta: { host: domain } }));
      }
      const [net, abuse] = await Promise.all([
        ripeGet<{ asns?: string[]; prefix?: string }>(`https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`),
        ripeGet<{ abuse_contacts?: string[]; authoritative_rir?: string }>(
          `https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${encodeURIComponent(ip)}`,
        ),
      ]);
      if (!net.data) {
        failures += 1;
        log.push(`${ip} network-info: ${net.error || "empty"}`);
      } else {
        const prefix = net.data.prefix ?? "";
        const asns = (net.data.asns ?? []).map((asn) => asn.replace(/^AS/i, "")).filter(Boolean).slice(0, 2);
        if (prefix) {
          entities.push(
            draft({
              type: "finding",
              value: `prefix:${prefix}`,
              severity: "info",
              relation: "prefix",
              source: "ripe",
              title: prefix,
              meta: { ip, prefix, linkTo: ip, linkRel: "covers" },
            }),
          );
        }
        log.push(`${ip} prefix ${prefix || "unknown"} AS ${asns.join(", ") || "none"}`);
        await Promise.all(
          asns.map(async (asn) => {
            const label = `AS${asn}`;
            const [overview, peer] = await Promise.all([
              ripeGet<{ holder?: string; announced?: boolean }>(`https://stat.ripe.net/data/as-overview/data.json?resource=${encodeURIComponent(label)}`),
              getText(`https://www.peeringdb.com/api/net?asn=${encodeURIComponent(asn)}`, { timeout: 8_000 }).catch(() => null),
            ]);
            const holder = overview.data?.holder ?? "";
            entities.push(
              draft({
                type: "asn",
                value: label,
                severity: "info",
                relation: "origin",
                source: "ripe",
                title: holder ? `${label} ${holder}` : label,
                meta: {
                  holder,
                  announced: overview.data?.announced === false ? "no" : "yes",
                  prefix,
                  linkTo: ip,
                  linkRel: "originates",
                },
              }),
            );
            if (!overview.data) log.push(`${label}: ${overview.error || "no overview"}`);
            if (!peer || peer.status !== 200) return;
            try {
              const body = JSON.parse(peer.text) as { data?: { name?: string; website?: string; info_scope?: string; info_type?: string }[] };
              const row = body.data?.[0];
              if (!row?.name) return;
              log.push(`PeeringDB ${label}: ${row.name}`);
              if (!row.website) return;
              entities.push(
                draft({
                  type: "url",
                  value: row.website,
                  severity: "info",
                  relation: "network-site",
                  source: "peeringdb",
                  title: `${row.name} website`,
                  meta: { asn: label, scope: row.info_scope ?? "", kind: row.info_type ?? "" },
                }),
              );
            } catch {
              log.push(`PeeringDB ${label}: unreadable`);
            }
          }),
        );
      }
      const contacts = abuse.data?.abuse_contacts ?? [];
      if (contacts.length) {
        for (const contact of contacts.slice(0, 3)) {
          if (!looksEmail(contact)) {
            log.push(`Abuse contact ${contact}`);
            continue;
          }
          entities.push(
            draft({
              type: "email",
              value: contact.toLowerCase(),
              severity: "info",
              relation: "abuse-contact",
              source: "ripe",
              title: contact.toLowerCase(),
              meta: { rir: abuse.data?.authoritative_rir ?? "", linkTo: ip, linkRel: "abuse-for" },
            }),
          );
        }
        log.push(`Abuse: ${contacts.slice(0, 3).join(", ")}`);
      } else if (abuse.error) {
        log.push(`${ip} abuse: ${abuse.error}`);
      }
    }
    if (!entities.length && failures) return fail("bgp", started, new Error("Routing lookups failed."), log);
    return finish("bgp", started, entities, log);
  } catch (error) {
    return fail("bgp", started, error, log);
  }
}

async function modGeo(kind: Kind, target: string, domain: string): Promise<ModuleResult> {
  const started = Date.now();
  const log: string[] = [];
  try {
    const ips = kind === "ip" ? [target] : await resolvePublicA(domain);
    if (!ips.length) return finish("geo", started, [], ["No public A record to geolocate."]);
    const entities: EntityDraft[] = [];
    let failures = 0;
    for (const ip of ips.slice(0, 2)) {
      const res = await getText(`https://ipwho.is/${encodeURIComponent(ip)}`, { timeout: 8_000 });
      if (res.status !== 200) {
        failures += 1;
        log.push(`${ip}: HTTP ${res.status}`);
        continue;
      }
      const data = JSON.parse(res.text) as {
        success?: boolean;
        message?: string;
        city?: string;
        region?: string;
        country?: string;
        country_code?: string;
        latitude?: number;
        longitude?: number;
        connection?: { asn?: number; org?: string; isp?: string };
        timezone?: { id?: string };
      };
      if (data.success === false) {
        failures += 1;
        log.push(`${ip}: ${data.message || "no geolocation"}`);
        continue;
      }
      const place = [data.city, data.region, data.country].filter(Boolean).join(", ");
      const org = data.connection?.org || data.connection?.isp || "";
      if (kind !== "ip") {
        entities.push(draft({ type: "ip", value: ip, severity: "info", relation: "resolves", source: "ipwho", title: ip, meta: { host: domain } }));
      }
      entities.push(
        draft({
          type: "finding",
          value: `geo:${ip}`,
          severity: "info",
          relation: "geolocation",
          source: "ipwho",
          title: org && place ? `${place} · ${org}` : place || org || ip,
          meta: {
            ip,
            city: data.city ?? "",
            region: data.region ?? "",
            country: data.country ?? "",
            countryCode: data.country_code ?? "",
            latitude: data.latitude != null ? String(data.latitude) : "",
            longitude: data.longitude != null ? String(data.longitude) : "",
            timezone: data.timezone?.id ?? "",
            org,
            note: "Approximate geolocation from a public IP database. Not a precise location.",
            linkTo: ip,
            linkRel: "located",
          },
        }),
      );
      if (data.connection?.asn) {
        entities.push(
          draft({
            type: "asn",
            value: `AS${data.connection.asn}`,
            severity: "info",
            relation: "origin",
            source: "ipwho",
            title: org ? `AS${data.connection.asn} ${org}` : `AS${data.connection.asn}`,
            meta: { linkTo: ip, linkRel: "originates" },
          }),
        );
      }
      log.push(`${ip}: ${place || "no city"}${org ? ` · ${org}` : ""}`);
    }
    if (!entities.length && failures) return fail("geo", started, new Error("Geolocation lookups failed."), log);
    return finish("geo", started, entities, log);
  } catch (error) {
    return fail("geo", started, error, log);
  }
}

async function modPdns(kind: Kind, target: string, domain: string): Promise<ModuleResult> {
  const started = Date.now();
  const query = kind === "ip" ? target : domain;
  if (kind !== "ip" && !isPublicHost(domain)) return fail("pdns", started, new Error("That host is not a public target."));
  try {
    const res = await getText(`https://api.mnemonic.no/pdns/v3/${encodeURIComponent(query)}?limit=20`, { timeout: 12_000 });
    if (res.status === 429) throw new Error("Mnemonic rate limit. Try again later.");
    if (res.status !== 200) throw new Error(`Passive DNS HTTP ${res.status}`);
    const data = JSON.parse(res.text) as {
      count?: number;
      data?: { query?: string; answer?: string; rrtype?: string; firstSeenTimestamp?: number; lastSeenTimestamp?: number; times?: number }[];
    };
    const rows = data.data ?? [];
    const wanted = new Set(["a", "aaaa", "cname", "mx", "ns", "ptr"]);
    const entities: EntityDraft[] = [];
    for (const row of rows) {
      const rr = (row.rrtype ?? "").toLowerCase();
      if (!wanted.has(rr)) continue;
      const first = seenDay(row.firstSeenTimestamp ?? 0);
      const last = seenDay(row.lastSeenTimestamp ?? 0);
      const times = String(row.times ?? "");
      if (kind === "ip") {
        const host = cleanName(row.query ?? "");
        if (!host || host === target.toLowerCase() || !host.includes(".")) continue;
        entities.push(
          draft({
            type: "domain",
            value: host,
            severity: "info",
            relation: "resolved-here",
            source: "mnemonic",
            title: host,
            meta: { rrtype: rr, first, last, times, host: target, note: "Name observed resolving to this address. Shared addresses are noisy." },
          }),
        );
        continue;
      }
      if (rr === "a" || rr === "aaaa") {
        const ip = (row.answer ?? "").trim().toLowerCase();
        if (!ip || isPrivateIp(ip)) continue;
        entities.push(
          draft({
            type: "ip",
            value: ip,
            severity: "info",
            relation: "historical-address",
            source: "mnemonic",
            title: `${rr.toUpperCase()} ${ip}`,
            meta: { rrtype: rr, first, last, times, host: domain },
          }),
        );
        continue;
      }
      const host = cleanName(row.answer ?? "");
      if (!host || host === domain || !host.includes(".")) continue;
      entities.push(
        draft({
          type: belongs(host, domain) && host !== domain ? "subdomain" : "domain",
          value: host,
          severity: "info",
          relation: rr,
          source: "mnemonic",
          title: `${rr.toUpperCase()} ${host}`,
          meta: { rrtype: rr, first, last, host: domain },
        }),
      );
    }
    const total = data.count ?? rows.length;
    const log = [
      kind === "ip"
        ? `${rows.length} of ${total} passive DNS rows. Shared addresses collect unrelated names.`
        : `${rows.length} of ${total} historical rows for ${domain}.`,
    ];
    return finish("pdns", started, entities, log, { truncated: total > rows.length });
  } catch (error) {
    return fail("pdns", started, error);
  }
}

async function modMalware(kind: Kind, target: string, domain: string): Promise<ModuleResult> {
  const started = Date.now();
  if (kind !== "ip" && !isPublicHost(domain)) return fail("malware", started, new Error("That host is not a public target."));
  const indicator = kind === "ip" ? `${target.includes(":") ? "IPv6" : "IPv4"}/${encodeURIComponent(target)}` : `domain/${encodeURIComponent(domain)}`;
  const subject = kind === "ip" ? target : domain;
  try {
    const res = await getText(`https://otx.alienvault.com/api/v1/indicators/${indicator}/malware?limit=8`, { timeout: 12_000 });
    if (res.status === 429) throw new Error("OTX rate limit. Try again later.");
    if (res.status !== 200) throw new Error(`OTX malware HTTP ${res.status}`);
    const data = JSON.parse(res.text) as {
      count?: number;
      data?: { hash?: string; date?: string; detections?: Record<string, string | null> }[];
    };
    const rows = (data.data ?? []).filter((row) => row.hash).slice(0, 8);
    if (!rows.length) return finish("malware", started, [], [`No OTX malware samples for ${subject}.`]);
    const entities: EntityDraft[] = [
      draft({
        type: "finding",
        value: `otx-malware:${subject}`,
        severity: "low",
        relation: "malware-association",
        source: "otx",
        title: `OTX lists ${data.count ?? rows.length} related samples`,
        meta: {
          count: String(data.count ?? rows.length),
          note: "Sample association only. Not proof this host is malicious or still serving the file.",
          host: subject,
        },
      }),
    ];
    for (const row of rows) {
      const names = Object.entries(row.detections ?? {})
        .filter((entry): entry is [string, string] => Boolean(entry[1]))
        .map(([engine, name]) => `${engine}: ${name}`);
      entities.push(
        draft({
          type: "finding",
          value: `otx:${row.hash}`,
          severity: names.length ? "medium" : "low",
          relation: "malware-sample",
          source: "otx",
          title: (names[0] || row.hash || "sample").slice(0, 140),
          meta: {
            hash: row.hash ?? "",
            date: row.date ?? "",
            detections: names.slice(0, 4).join(" | "),
            host: subject,
            linkTo: subject,
            linkRel: "associated-with",
          },
        }),
      );
    }
    const total = data.count ?? rows.length;
    return finish("malware", started, entities, [`${rows.length} of ${total} OTX samples. Association only.`], {
      truncated: total > rows.length,
    });
  } catch (error) {
    return fail("malware", started, error);
  }
}

async function modRank(domain: string): Promise<ModuleResult> {
  const started = Date.now();
  const name = domain.replace(/^www\./, "");
  if (!isPublicHost(name)) return fail("rank", started, new Error("That host is not a public target."));
  try {
    const res = await getText(`https://tranco-list.eu/api/ranks/domain/${encodeURIComponent(name)}`, { timeout: 10_000 });
    if (res.status !== 200) throw new Error(`Tranco HTTP ${res.status}`);
    const data = JSON.parse(res.text) as { ranks?: { date?: string; rank?: number }[] };
    const latest = data.ranks?.[0];
    if (!latest?.rank) {
      return finish(
        "rank",
        started,
        [draft({ type: "finding", value: `tranco:${name}`, severity: "info", relation: "popularity", source: "tranco", title: "Not in the recent Tranco list", meta: { domain: name } })],
        [`${name} is not in the recent Tranco top list.`],
      );
    }
    return finish(
      "rank",
      started,
      [
        draft({
          type: "finding",
          value: `tranco:${name}`,
          severity: "info",
          relation: "popularity",
          source: "tranco",
          title: `Tranco rank ${latest.rank.toLocaleString("en-US")}`,
          meta: { domain: name, rank: String(latest.rank), date: latest.date ?? "" },
        }),
      ],
      [`Tranco rank ${latest.rank} on ${latest.date ?? "the latest list"}.`],
    );
  } catch (error) {
    return fail("rank", started, error);
  }
}

async function modCode(kind: Kind, target: string, domain: string): Promise<ModuleResult> {
  const started = Date.now();
  const log: string[] = [];
  const entities: EntityDraft[] = [];
  let errors = 0;

  async function grab(url: string): Promise<Got | null> {
    try {
      return await getText(url, { timeout: 8_000, headers: { accept: "application/json" } });
    } catch (error) {
      errors += 1;
      log.push(error instanceof Error ? error.message : "Request failed");
      return null;
    }
  }

  function limited(status: number, label: string): boolean {
    if (status === 403 || status === 429) {
      errors += 1;
      log.push(`${label} rate limit.`);
      return true;
    }
    return false;
  }

  try {
    if (kind === "username") {
      const repos = await grab(`https://api.github.com/users/${encodeURIComponent(target)}/repos?sort=updated&per_page=8&type=owner`);
      if (repos?.status === 404) log.push("No public GitHub user.");
      else if (repos && !limited(repos.status, "GitHub") && repos.status !== 200) {
        errors += 1;
        log.push(`GitHub repos HTTP ${repos.status}`);
      } else if (repos?.status === 200) {
        const rows = JSON.parse(repos.text) as { html_url?: string; name?: string; description?: string; stargazers_count?: number; fork?: boolean }[];
        const owned = rows.filter((row) => row.html_url && !row.fork).slice(0, 8);
        for (const row of owned) {
          entities.push(
            draft({
              type: "url",
              value: row.html_url || "",
              severity: "info",
              relation: "public-repo",
              source: "github",
              title: row.name || row.html_url || "Repository",
              meta: { description: (row.description ?? "").slice(0, 160), stars: String(row.stargazers_count ?? "") },
            }),
          );
        }
        log.push(`GitHub repos: ${owned.length}.`);
      }
      const gists = await grab(`https://api.github.com/users/${encodeURIComponent(target)}/gists?per_page=5`);
      if (gists?.status === 200) {
        const rows = JSON.parse(gists.text) as { html_url?: string; description?: string }[];
        for (const row of rows.slice(0, 5)) {
          if (!row.html_url) continue;
          entities.push(
            draft({
              type: "url",
              value: row.html_url,
              severity: "info",
              relation: "public-gist",
              source: "github",
              title: row.description?.slice(0, 80) || "Gist",
            }),
          );
        }
        if (rows.length) log.push(`GitHub gists: ${rows.length}.`);
      }
      const projects = await grab(`https://gitlab.com/api/v4/users/${encodeURIComponent(target)}/projects?simple=true&per_page=6&order_by=updated_at`);
      if (projects?.status === 200) {
        const rows = JSON.parse(projects.text) as { web_url?: string; name?: string; description?: string }[];
        for (const row of rows.slice(0, 6)) {
          if (!row.web_url) continue;
          entities.push(
            draft({
              type: "url",
              value: row.web_url,
              severity: "info",
              relation: "public-repo",
              source: "gitlab",
              title: row.name || row.web_url,
              meta: { description: (row.description ?? "").slice(0, 160) },
            }),
          );
        }
        if (rows.length) log.push(`GitLab projects: ${rows.length}.`);
      } else if (projects && projects.status !== 404) {
        log.push(`GitLab HTTP ${projects.status}`);
      }
    } else {
      const needle = kind === "email" ? target : domain;
      const userQuery = kind === "email" ? `"${needle}" in:email` : `${needle} in:blog`;
      const users = await grab(`https://api.github.com/search/users?q=${encodeURIComponent(userQuery)}&per_page=5`);
      if (users && !limited(users.status, "GitHub")) {
        if (users.status !== 200) {
          errors += 1;
          log.push(`GitHub users HTTP ${users.status}`);
        } else {
          const data = JSON.parse(users.text) as { total_count?: number; items?: { html_url?: string; login?: string }[] };
          let kept = 0;
          for (const item of (data.items ?? []).slice(0, 5)) {
            if (!item.html_url || !item.login) continue;
            if (kind === "email") {
              entities.push(
                draft({
                  type: "profile",
                  value: item.html_url,
                  severity: "info",
                  relation: "profile",
                  source: "github",
                  title: `GitHub ${item.login}`,
                  meta: { site: "GitHub", note: "Matched GitHub's email index. The address itself is not returned." },
                }),
              );
            } else {
              const profile = await grab(`https://api.github.com/users/${encodeURIComponent(item.login)}`);
              if (!profile || profile.status !== 200) continue;
              const body = JSON.parse(profile.text) as { blog?: string; name?: string };
              if (!hostEquals(body.blog ?? "", domain)) continue;
              entities.push(
                draft({
                  type: "profile",
                  value: item.html_url,
                  severity: "info",
                  relation: "profile",
                  source: "github",
                  title: `GitHub ${item.login}`,
                  meta: { site: "GitHub", blog: body.blog ?? "", name: body.name ?? "" },
                }),
              );
            }
            entities.push(
              draft({
                type: "username",
                value: item.login,
                severity: "info",
                relation: "also-known-as",
                source: "github",
                title: item.login,
                meta: { via: kind === "email" ? "email-index" : "blog" },
              }),
            );
            kept += 1;
          }
          log.push(`GitHub users kept ${kept} of ${data.total_count ?? 0}.`);
        }
      }
      if (kind !== "email") {
        const repos = await grab(`https://api.github.com/search/repositories?q=${encodeURIComponent(`${domain} in:homepage`)}&per_page=5`);
        if (repos && !limited(repos.status, "GitHub")) {
          if (repos.status !== 200) {
            errors += 1;
            log.push(`GitHub repos HTTP ${repos.status}`);
          } else {
            const data = JSON.parse(repos.text) as {
              items?: { html_url?: string; full_name?: string; homepage?: string; description?: string }[];
            };
            let kept = 0;
            for (const item of data.items ?? []) {
              if (!item.html_url || !hostEquals(item.homepage ?? "", domain)) continue;
              entities.push(
                draft({
                  type: "url",
                  value: item.html_url,
                  severity: "info",
                  relation: "homepage",
                  source: "github",
                  title: item.full_name || item.html_url,
                  meta: { homepage: item.homepage ?? "", description: (item.description ?? "").slice(0, 140) },
                }),
              );
              kept += 1;
            }
            log.push(`GitHub homepages kept ${kept}.`);
          }
        }
      }
      const issues = await grab(`https://api.github.com/search/issues?q=${encodeURIComponent(`"${needle}" in:title`)}&per_page=5`);
      if (issues && !limited(issues.status, "GitHub")) {
        if (issues.status !== 200) {
          errors += 1;
          log.push(`GitHub issues HTTP ${issues.status}`);
        } else {
          const data = JSON.parse(issues.text) as { items?: { html_url?: string; title?: string; state?: string }[] };
          let kept = 0;
          for (const item of (data.items ?? []).slice(0, 5)) {
            if (!item.html_url || !item.title || !item.title.toLowerCase().includes(needle.toLowerCase())) continue;
            entities.push(
              draft({
                type: "url",
                value: item.html_url,
                severity: "info",
                relation: "mentioned-in",
                source: "github",
                title: item.title.slice(0, 140),
                meta: { state: item.state ?? "" },
              }),
            );
            kept += 1;
          }
          log.push(`GitHub issue titles kept ${kept}.`);
        }
      }
    }
  } catch (error) {
    return fail("code", started, error, log);
  }

  if (!entities.length && errors > 0) return fail("code", started, new Error("Public code sources failed."), log);
  return finish("code", started, entities, log.length ? log : ["No public code mentions."]);
}

async function modDnssec(domain: string): Promise<ModuleResult> {
  const started = Date.now();
  const log: string[] = [];
  try {
    const res = await getText(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=DS`);
    if (res.status !== 200) return fail("dnssec", started, new Error(`DNS HTTP ${res.status}`), log);
    const data = JSON.parse(res.text) as { Status?: number; Answer?: { data?: string }[] };
    const published = data.Status === 0 && (data.Answer?.length ?? 0) > 0;
    log.push(published ? "DS record published." : "No DS record in the public resolver.");
    return finish("dnssec", started, [
      draft({
        type: "finding",
        value: `dnssec:${domain}`,
        severity: "info",
        relation: "dnssec",
        source: "dns",
        title: published ? "DNSSEC DS published" : "No DS record published",
        meta: { domain },
      }),
    ], log);
  } catch (error) {
    return fail("dnssec", started, error, log);
  }
}

async function modBlocklist(kind: Kind, target: string, domain: string): Promise<ModuleResult> {
  const started = Date.now();
  const host = kind === "ip" ? target : domain;
  const log: string[] = [];
  try {
    const res = await fetch("https://urlhaus-api.abuse.ch/v1/host/", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "user-agent": UA, accept: "application/json" },
      body: new URLSearchParams({ host }),
      signal: AbortSignal.timeout(12_000),
    });
    const text = await res.text();
    if (res.status !== 200) return fail("blocklist", started, new Error(`URLhaus HTTP ${res.status}`), log);
    const data = JSON.parse(text) as { query_status?: string; url_count?: number };
    const listed = data.query_status === "ok" || data.query_status === "is_host";
    log.push(listed ? `URLhaus lists ${host}.` : "URLhaus has no malware URL for this host.");
    if (!listed) return finish("blocklist", started, [], log);
    return finish("blocklist", started, [
      draft({
        type: "finding",
        value: `urlhaus:${host}`,
        severity: "high",
        relation: "blocklist",
        source: "urlhaus",
        title: "Listed on URLhaus",
        meta: { host, urls: String(data.url_count ?? "") },
      }),
    ], log);
  } catch (error) {
    return fail("blocklist", started, error, log);
  }
}

async function modGreen(domain: string): Promise<ModuleResult> {
  const started = Date.now();
  const log: string[] = [];
  try {
    const res = await getText(`https://api.thegreenwebfoundation.org/greencheck/${encodeURIComponent(domain)}`);
    if (res.status !== 200) return fail("green", started, new Error(`Green Web HTTP ${res.status}`), log);
    const data = JSON.parse(res.text) as { green?: boolean; hosted_by?: string; data?: boolean };
    const green = Boolean(data.green);
    log.push(green ? "Green Web lists this host." : "Not in the Green Web dataset.");
    return finish("green", started, [
      draft({
        type: "finding",
        value: `green:${domain}`,
        severity: "info",
        relation: "green-host",
        source: "greenweb",
        title: green ? "Listed as green hosted" : "Not in the Green Web dataset",
        meta: { host: data.hosted_by ?? "" },
      }),
    ], log);
  } catch (error) {
    return fail("green", started, error, log);
  }
}

async function modHandles(username: string): Promise<ModuleResult> {
  const started = Date.now();
  const user = username.replace(/^@/, "");
  const log: string[] = [];
  const entities: EntityDraft[] = [];
  const checks: { site: string; url: string; hit: (status: number, text: string) => boolean }[] = [
    {
      site: "Bluesky",
      url: `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(user)}`,
      hit: (status) => status === 200,
    },
    {
      site: "Reddit",
      url: `https://www.reddit.com/user/${encodeURIComponent(user)}/about.json`,
      hit: (status, text) => status === 200 && text.includes(`"name"`),
    },
    {
      site: "Hacker News",
      url: `https://hacker-news.firebaseio.com/v0/user/${encodeURIComponent(user)}.json`,
      hit: (status, text) => status === 200 && text.trim() !== "null" && text.includes(`"id"`),
    },
    {
      site: "Chess.com",
      url: `https://api.chess.com/pub/player/${encodeURIComponent(user)}`,
      hit: (status) => status === 200,
    },
    {
      site: "Dev.to",
      url: `https://dev.to/api/users/by_username?url=${encodeURIComponent(user)}`,
      hit: (status, text) => status === 200 && text.includes(`"username"`),
    },
    {
      site: "Lemmy",
      url: `https://lemmy.world/api/v3/user?username=${encodeURIComponent(user)}`,
      hit: (status, text) => status === 200 && text.includes(`"person"`),
    },
    {
      site: "Wikipedia",
      url: `https://en.wikipedia.org/w/api.php?action=query&list=users&ususers=${encodeURIComponent(user)}&format=json`,
      hit: (status, text) => status === 200 && text.includes(`"userid"`),
    },
  ];
  let errors = 0;
  await Promise.all(
    checks.map(async (check) => {
      try {
        const res = await getText(check.url, { timeout: 8_000, max: 80_000 });
        if (check.hit(res.status, res.text)) {
          entities.push(
            draft({
              type: "profile",
              value: check.url,
              severity: "info",
              relation: "account-may-exist",
              source: "handles",
              title: `${check.site}: ${user}`,
              meta: { site: check.site, note: "The name is registered. That does not show who operates it." },
            }),
          );
          log.push(`${check.site}: name is registered.`);
        } else {
          log.push(`${check.site}: no account.`);
        }
      } catch {
        errors += 1;
        log.push(`${check.site}: lookup failed.`);
      }
    }),
  );
  if (!entities.length && errors === checks.length) return fail("handles", started, new Error("Every username site failed."), log);
  return finish("handles", started, entities, log);
}

async function runModule(id: string, input: RunInput, domain: string): Promise<ModuleResult> {
  switch (id) {
    case "ct":
      return modCt(domain);
    case "rdap":
      return modRdap(input.kind, input.target, domain);
    case "dns":
      return modDns(input.kind, input.target, domain);
    case "internetdb":
      return modInternetDb(input.kind, input.target, domain);
    case "wayback":
      return modWayback(domain);
    case "otx":
      return modOtx(domain);
    case "urlscan":
      return modUrlscan(domain);
    case "reputation":
      return modReputation(input.kind, input.target, domain, input.vtKey ?? "");
    case "profiles":
      return modProfiles(input.target);
    case "breach":
      return modBreach(input.target, input.hibpKey ?? "");
    case "surface":
      return modSurface(input.kind, input.target, domain, input.authorized);
    case "mail":
      return modMail(input.kind, input.target, domain);
    case "bgp":
      return modBgp(input.kind, input.target, domain);
    case "geo":
      return modGeo(input.kind, input.target, domain);
    case "pdns":
      return modPdns(input.kind, input.target, domain);
    case "malware":
      return modMalware(input.kind, input.target, domain);
    case "rank":
      return modRank(domain);
    case "code":
      return modCode(input.kind, input.target, domain);
    case "dnssec":
      return modDnssec(domain);
    case "blocklist":
      return modBlocklist(input.kind, input.target, domain);
    case "green":
      return modGreen(domain);
    case "handles":
      return modHandles(input.target);
    default:
      return fail(id, Date.now(), new Error("Unknown module"));
  }
}

export async function execute(input: RunInput): Promise<{ results: ModuleResult[] }> {
  if (!rateOk()) {
    return {
      results: input.modules.map((module) => fail(module, Date.now(), new Error("Too many lookups. Wait a minute."))),
    };
  }
  const kind = input.kind;
  const target = normalizeTarget(kind, input.target);
  assertTarget(kind, target);
  const domain = hostFrom(kind, target);
  const hostModules = ["ct", "rdap", "dns", "internetdb", "wayback", "otx", "urlscan", "reputation", "surface", "mail", "bgp", "geo", "pdns", "malware", "rank", "code", "dnssec", "blocklist", "green"];
  if (hostModules.some((id) => input.modules.includes(id))) {
    if (kind !== "ip" && kind !== "email" && kind !== "username" && kind !== "phone" && !isPublicHost(domain)) {
      throw new Error("Enter a public host.");
    }
  }
  const localOnly = new Set(["dorks", "pivots"]);
  const modules = input.modules.filter((id) => {
    const def = moduleDef(id);
    return Boolean(def && !localOnly.has(id) && def.kinds.includes(kind));
  });
  if (modules.includes("surface") && !input.authorized) {
    throw new Error("Confirm authorization before a surface review.");
  }
  const normalized: RunInput = {
    ...input,
    target,
    hibpKey: input.hibpKey?.slice(0, 128) ?? "",
    vtKey: input.vtKey?.slice(0, 128) ?? "",
    modules,
  };
  const results: ModuleResult[] = [];
  for (const id of modules) {
    try {
      results.push(await runModule(id, normalized, domain));
    } catch (error) {
      results.push(fail(id, Date.now(), error));
    }
  }
  return { results };
}
