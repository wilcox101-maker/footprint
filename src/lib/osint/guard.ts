import type { Kind } from "@/lib/osint/types";

const HOST =
  /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i;

export function isIpV4(value: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (!m) return false;
  return m.slice(1).every((n) => Number(n) <= 255);
}

export function isIpV6(value: string): boolean {
  const v = value.toLowerCase();
  if (!v.includes(":") || v.length > 64) return false;
  if (!/^[0-9a-f:]+$/.test(v)) return false;
  const halves = v.split("::");
  if (halves.length > 2) return false;
  const groups = halves.map((h) => (h ? h.split(":") : []));
  const count = groups.reduce((n, g) => n + g.length, 0);
  if (halves.length === 1 && count !== 8) return false;
  if (halves.length === 2 && count > 7) return false;
  return groups.every((g) => g.every((p) => p.length >= 1 && p.length <= 4));
}

export function isIp(value: string): boolean {
  return isIpV4(value) || isIpV6(value);
}

/** True for loopback, private, link-local, CGNAT, multicast, and unspecified. */
export function isPrivateIp(ip: string): boolean {
  let value = ip.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (value.startsWith("::ffff:")) value = value.slice(7);
  if (isIpV4(value)) {
    const [a, b] = value.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && (b === 168 || b === 0)) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a >= 224) return true;
    return false;
  }
  if (value === "::1" || value === "::") return true;
  if (value.startsWith("fc") || value.startsWith("fd")) return true;
  if (/^fe[89ab]/.test(value)) return true;
  if (value.startsWith("ff")) return true;
  return false;
}

export function isPublicHost(hostname: string): boolean {
  const host = hostname.trim().toLowerCase().replace(/\.$/, "");
  if (!host || host.length > 253) return false;
  if (host === "localhost" || host.endsWith(".localhost")) return false;
  if (host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".home.arpa")) return false;
  if (host === "metadata.google.internal" || host.endsWith(".internal.")) return false;
  if (/^\d+$/.test(host)) return false;
  if (isIp(host)) return !isPrivateIp(host);
  return HOST.test(host);
}

export function isEmail(value: string): boolean {
  return /^[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,63}$/i.test(value) && value.length <= 254;
}

export function isUsername(value: string): boolean {
  return /^[a-zA-Z0-9][a-zA-Z0-9_-]{1,38}$/.test(value);
}

export function detectKind(raw: string): Kind {
  const s = raw.trim();
  if (/^https?:\/\//i.test(s)) return "url";
  if (isEmail(s)) return "email";
  if (isIp(s)) return "ip";
  const hostish = s.replace(/^[a-z]+:\/\//i, "").split("/")[0]?.split("?")[0] ?? "";
  const withoutPort = hostish.replace(/:\d+$/, "");
  if (isPublicHost(withoutPort) && withoutPort.includes(".")) return "domain";
  return "username";
}

export function normalizeTarget(kind: Kind, raw: string): string {
  let s = raw.trim();
  if (kind === "email") return s.toLowerCase();
  if (kind === "username") return s.replace(/^@/, "");
  if (kind === "ip") return s.replace(/^\[|\]$/g, "").toLowerCase();
  if (kind === "url") {
    if (!/^https?:\/\//i.test(s)) s = `https://${s}`;
    const url = new URL(s);
    url.hash = "";
    return url.toString();
  }
  s = s.replace(/^[a-z]+:\/\//i, "");
  s = s.split("/")[0]?.split("?")[0]?.split("#")[0] ?? s;
  s = s.replace(/:\d+$/, "");
  return s.replace(/\.$/, "").toLowerCase();
}

export function hostFrom(kind: Kind, target: string): string {
  if (kind === "url") {
    try {
      return new URL(target).hostname.toLowerCase();
    } catch {
      return "";
    }
  }
  if (kind === "email") return target.split("@")[1]?.toLowerCase() ?? "";
  return target.toLowerCase();
}

export function assertTarget(kind: Kind, target: string): void {
  if (kind === "email" && !isEmail(target)) throw new Error("Enter a single email address.");
  if (kind === "username" && !isUsername(target)) {
    throw new Error("Usernames here are 2–39 letters, numbers, underscores, or hyphens.");
  }
  if (kind === "ip") {
    if (!isIp(target) || isPrivateIp(target)) throw new Error("Enter a public IP address.");
  }
  if (kind === "domain" && !isPublicHost(target)) throw new Error("Enter a public domain name.");
  if (kind === "url") {
    let url: URL;
    try {
      url = new URL(target);
    } catch {
      throw new Error("Enter a full http or https URL.");
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("Only http and https URLs.");
    if (url.port && url.port !== "80" && url.port !== "443") throw new Error("Only ports 80 and 443.");
    if (!isPublicHost(url.hostname)) throw new Error("That host is not a public target.");
  }
}
