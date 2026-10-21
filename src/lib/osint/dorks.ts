import type { Kind, ModuleResult } from "@/lib/osint/types";

const TEMPLATES: { title: string; q: (host: string) => string }[] = [
  { title: "Entire site", q: (h) => `site:${h}` },
  { title: "Documents", q: (h) => `site:${h} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx)` },
  { title: "Exposed indexes", q: (h) => `site:${h} intitle:"index of"` },
  { title: "Common config leftovers", q: (h) => `site:${h} (ext:env OR ext:log OR ext:bak OR ext:sql OR ext:yml)` },
  { title: "Login and admin paths", q: (h) => `site:${h} (inurl:admin OR inurl:login OR inurl:dashboard)` },
  { title: "Third-party mentions", q: (h) => `"${h}" -site:${h}` },
  { title: "Paste sites", q: (h) => `"${h}" (site:pastebin.com OR site:ghostbin.com OR site:rentry.co)` },
  { title: "Public code", q: (h) => `"${h}" (site:github.com OR site:gitlab.com)` },
];

/** Search links only. The workstation never fetches search-engine results. */
export function dorkResult(host: string): ModuleResult {
  const started = Date.now();
  const entities = TEMPLATES.map((t) => {
    const query = t.q(host);
    const url = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
    return {
      type: "url" as const,
      value: url,
      severity: "info" as const,
      relation: "search-link",
      source: "dorks",
      title: t.title,
      meta: { query, host },
    };
  });
  return {
    module: "dorks",
    ok: true,
    truncated: false,
    durationMs: Date.now() - started,
    entities,
    log: [
      `Built ${entities.length} search links for ${host}.`,
      "Open them yourself. Do not use results to access systems you are not allowed to test.",
    ],
  };
}

type Link = { title: string; url: string };

/** Outbound links only. Opening one does not confirm an account or a record. */
export function pivotResult(kind: Kind, target: string, host: string): ModuleResult {
  const started = Date.now();
  const enc = encodeURIComponent;
  let links: Link[] = [];
  if (kind === "username") {
    const user = target.replace(/^@/, "");
    links = [
      ["GitHub", `https://github.com/${enc(user)}`],
      ["GitLab", `https://gitlab.com/${enc(user)}`],
      ["Codeberg", `https://codeberg.org/${enc(user)}`],
      ["X", `https://x.com/${enc(user)}`],
      ["Reddit", `https://www.reddit.com/user/${enc(user)}`],
      ["Instagram", `https://www.instagram.com/${enc(user)}/`],
      ["Telegram", `https://t.me/${enc(user)}`],
      ["YouTube", `https://www.youtube.com/@${enc(user)}`],
      ["Twitch", `https://www.twitch.tv/${enc(user)}`],
      ["Steam", `https://steamcommunity.com/id/${enc(user)}`],
      ["Keybase", `https://keybase.io/${enc(user)}`],
      ["Medium", `https://medium.com/@${enc(user)}`],
      ["Hacker News", `https://news.ycombinator.com/user?id=${enc(user)}`],
    ].map(([title, url]) => ({ title: title!, url: url! }));
  } else if (kind === "email") {
    links = [
      { title: "Google", url: `https://www.google.com/search?q=${enc(`"${target}"`)}` },
      { title: "GitHub search", url: `https://github.com/search?q=${enc(target)}&type=code` },
      { title: "Have I Been Pwned", url: "https://haveibeenpwned.com/" },
      { title: "IntelX", url: `https://intelx.io/?s=${enc(target)}` },
      { title: "Paste sites", url: `https://www.google.com/search?q=${enc(`"${target}" (site:pastebin.com OR site:rentry.co)`)}` },
    ];
  } else if (kind === "ip") {
    links = [
      { title: "Shodan", url: `https://www.shodan.io/host/${enc(target)}` },
      { title: "Censys", url: `https://search.censys.io/hosts/${enc(target)}` },
      { title: "VirusTotal", url: `https://www.virustotal.com/gui/ip-address/${enc(target)}` },
      { title: "GreyNoise", url: `https://viz.greynoise.io/ip/${enc(target)}` },
      { title: "AbuseIPDB", url: `https://www.abuseipdb.com/check/${enc(target)}` },
      { title: "bgp.tools", url: `https://bgp.tools/prefix/${enc(target)}` },
      { title: "Hurricane Electric", url: `https://bgp.he.net/ip/${enc(target)}` },
      { title: "IPinfo", url: `https://ipinfo.io/${enc(target)}` },
      { title: "urlscan", url: `https://urlscan.io/ip/${enc(target)}` },
    ];
  } else {
    const name = host || target;
    links = [
      { title: "crt.sh", url: `https://crt.sh/?q=${enc(name)}` },
      { title: "urlscan", url: `https://urlscan.io/domain/${enc(name)}` },
      { title: "VirusTotal", url: `https://www.virustotal.com/gui/domain/${enc(name)}` },
      { title: "Shodan", url: `https://www.shodan.io/search?query=${enc(`hostname:${name}`)}` },
      { title: "Censys", url: `https://search.censys.io/search?resource=hosts&q=${enc(name)}` },
      { title: "Wayback", url: `https://web.archive.org/web/*/${name}` },
      { title: "SecurityTrails", url: `https://securitytrails.com/domain/${enc(name)}/dns` },
      { title: "bgp.tools", url: `https://bgp.tools/search?q=${enc(name)}` },
      { title: "BuiltWith", url: `https://builtwith.com/${enc(name)}` },
      { title: "PublicWWW", url: `https://publicwww.com/websites/${enc(`"${name}"`)}/` },
      { title: "IntelX", url: `https://intelx.io/?s=${enc(name)}` },
    ];
  }
  return {
    module: "pivots",
    ok: true,
    truncated: false,
    durationMs: Date.now() - started,
    entities: links.map((link) => ({
      type: "url" as const,
      value: link.url,
      severity: "info" as const,
      relation: "pivot-link",
      source: "pivots",
      title: link.title,
      meta: { host: host || target },
    })),
    log: [
      `Built ${links.length} pivot links.`,
      "Open them yourself. A link is not confirmation that an account, certificate, or record exists.",
    ],
  };
}
