import type { Kind } from "@/lib/osint/types";

export type ModuleDef = {
  id: string;
  label: string;
  detail: string;
  group: string;
  kinds: Kind[];
  /** False only for the single authorized surface review. */
  passive: boolean;
};

/**
 * Module registry. To add a source:
 * 1. Add a row here (id, kinds, whether it is passive).
 * 2. Handle that id in `runModule` inside `engine.server.ts`
 *    (or in `dorks.ts` and `run-client.ts` if it needs no network).
 * 3. Keep new modules passive unless they are a handful of ordinary
 *    GETs against a host the operator has marked as authorized.
 */
export const MODULES: ModuleDef[] = [
  {
    id: "ct",
    label: "Certificate transparency",
    detail: "Names published on public certificates (Cert Spotter, crt.sh fallback).",
    group: "Names and DNS",
    kinds: ["domain", "url"],
    passive: true,
  },
  {
    id: "dns",
    label: "DNS records",
    detail: "A, AAAA, MX, NS, TXT, CNAME, SOA — or PTR for an IP.",
    group: "Names and DNS",
    kinds: ["domain", "url", "ip"],
    passive: true,
  },
  {
    id: "pdns",
    label: "Passive DNS",
    detail: "Historical resolutions from Mnemonic. Not a live name brute force.",
    group: "Names and DNS",
    kinds: ["domain", "url", "ip"],
    passive: true,
  },
  {
    id: "rdap",
    label: "Registration (RDAP)",
    detail: "Registrar, dates, nameservers, or network allocation.",
    group: "Names and DNS",
    kinds: ["domain", "url", "ip"],
    passive: true,
  },
  {
    id: "mail",
    label: "Mail posture",
    detail: "MX, SPF, DMARC, and MTA-STS from public DNS. Emails also get role and disposable checks.",
    group: "Names and DNS",
    kinds: ["domain", "url", "email"],
    passive: true,
  },
  {
    id: "bgp",
    label: "Routing and ASN",
    detail: "RIPEstat prefix, AS holder, abuse contact, and PeeringDB.",
    group: "Network",
    kinds: ["domain", "url", "ip"],
    passive: true,
  },
  {
    id: "geo",
    label: "Geolocation",
    detail: "Approximate city and network from ipwho.is. Not a precise location.",
    group: "Network",
    kinds: ["domain", "url", "ip"],
    passive: true,
  },
  {
    id: "internetdb",
    label: "InternetDB",
    detail: "Shodan’s free InternetDB view of ports, hostnames, and listed CVEs.",
    group: "Network",
    kinds: ["domain", "url", "ip"],
    passive: true,
  },
  {
    id: "malware",
    label: "Malware association",
    detail: "Public OTX sample associations. A hit is not proof the host is malicious.",
    group: "Network",
    kinds: ["domain", "url", "ip"],
    passive: true,
  },
  {
    id: "rank",
    label: "Popularity rank",
    detail: "Latest Tranco list rank, when the domain is listed.",
    group: "Network",
    kinds: ["domain", "url"],
    passive: true,
  },
  {
    id: "wayback",
    label: "Wayback Machine",
    detail: "Historical URLs from the Internet Archive CDX index.",
    group: "History and mentions",
    kinds: ["domain", "url"],
    passive: true,
  },
  {
    id: "otx",
    label: "OTX URL history",
    detail: "Public AlienVault OTX URLs seen for the domain.",
    group: "History and mentions",
    kinds: ["domain", "url"],
    passive: true,
  },
  {
    id: "urlscan",
    label: "urlscan.io",
    detail: "Recent public urlscan submissions for the domain.",
    group: "History and mentions",
    kinds: ["domain", "url"],
    passive: true,
  },
  {
    id: "code",
    label: "Public code",
    detail: "GitHub and GitLab repos, homepages, and issue titles. No secret scanning.",
    group: "History and mentions",
    kinds: ["domain", "url", "email", "username"],
    passive: true,
  },
  {
    id: "dorks",
    label: "Search links",
    detail: "Google dork links to open yourself. Nothing is scraped.",
    group: "Links to open",
    kinds: ["domain", "url"],
    passive: true,
  },
  {
    id: "pivots",
    label: "Pivot links",
    detail: "Shodan, crt.sh, profile pages, and similar. A link is not a confirmed hit.",
    group: "Links to open",
    kinds: ["domain", "url", "email", "username", "ip"],
    passive: true,
  },
  {
    id: "reputation",
    label: "VirusTotal",
    detail: "Optional. Uses a key you store in this browser, if you add one.",
    group: "Identity",
    kinds: ["domain", "url", "ip"],
    passive: true,
  },
  {
    id: "profiles",
    label: "Public profiles",
    detail: "Stable public APIs (GitHub, GitLab, Mastodon, and others). Not a full Maigret sweep.",
    group: "Identity",
    kinds: ["username"],
    passive: true,
  },
  {
    id: "breach",
    label: "Breach names",
    detail: "Breach titles from XposedOrNot, plus Have I Been Pwned if you add a key. No passwords.",
    group: "Identity",
    kinds: ["email"],
    passive: true,
  },
  {
    id: "surface",
    label: "Surface review",
    detail: "Homepage, robots.txt, sitemap, and security.txt only. Requires authorization.",
    group: "Authorized",
    kinds: ["domain", "url"],
    passive: false,
  },
];

export const MODULE_IDS = new Set(MODULES.map((m) => m.id));

export function moduleDef(id: string): ModuleDef | undefined {
  return MODULES.find((m) => m.id === id);
}

export function modulesFor(kind: Kind): ModuleDef[] {
  return MODULES.filter((m) => m.kinds.includes(kind));
}

export type Preset = {
  id: string;
  label: string;
  blurb: string;
  kind: Kind;
  modules: string[];
  needsAuth?: boolean;
};

export const PRESETS: Preset[] = [
  {
    id: "domain",
    label: "Passive domain sweep",
    blurb: "Certificates, DNS, mail, routing, passive DNS, archives, and links.",
    kind: "domain",
    modules: [
      "ct",
      "rdap",
      "dns",
      "mail",
      "bgp",
      "geo",
      "pdns",
      "internetdb",
      "malware",
      "rank",
      "wayback",
      "otx",
      "urlscan",
      "code",
      "dorks",
      "pivots",
    ],
  },
  {
    id: "user",
    label: "Username footprint",
    blurb: "Public profile APIs, repos, and profile pages to open yourself.",
    kind: "username",
    modules: ["profiles", "code", "pivots"],
  },
  {
    id: "email",
    label: "Email and breach names",
    blurb: "Breach titles, mail posture, and public code mentions. No passwords.",
    kind: "email",
    modules: ["breach", "mail", "code", "pivots"],
  },
  {
    id: "ip",
    label: "IP intelligence",
    blurb: "Registration, routing, geolocation, passive DNS, and InternetDB.",
    kind: "ip",
    modules: ["rdap", "dns", "bgp", "geo", "pdns", "internetdb", "malware", "pivots"],
  },
  {
    id: "surface",
    label: "Authorized surface review",
    blurb: "Ordinary requests for the homepage, robots.txt, and security.txt.",
    kind: "url",
    modules: ["surface", "dns", "rdap"],
    needsAuth: true,
  },
];

export function presetFor(kind: Kind): Preset {
  return PRESETS.find((p) => p.kind === kind) ?? PRESETS[0];
}
