# Modules

Each module is a public source or a set of links. Passive modules do not attack the target. The only module that requests the site itself is **Surface review**, and it stays off until you confirm authorization.

To add a source later: add a row in `src/lib/osint/catalog.ts`, handle that id in `runModule` in `src/lib/osint/engine.server.ts`, and keep it passive unless it is a few ordinary page fetches against a host you marked as authorized. Link-only modules (`dorks`, `pivots`, `phone`) run in the browser and do not need a server lookup.

## Names and DNS

| Module | What you get |
|---|---|
| Certificate transparency | Names on public certificates, from Cert Spotter with a crt.sh fallback. |
| DNS records | A, AAAA, MX, NS, TXT, CNAME, SOA. An IP gets PTR. |
| Passive DNS | Historical resolutions from Mnemonic. Not a brute force of names. |
| Registration (RDAP) | Registrar, dates, nameservers, or the network allocation. Published contact fields are stored when the registry prints them. |
| Mail posture | MX, SPF, DMARC, and MTA-STS. An email also gets role-account and disposable-domain notes. |
| DNSSEC | Whether a DS record is published. Missing DNSSEC is noted. It is not scored as a breach. |

## Network

| Module | What you get |
|---|---|
| Routing and ASN | RIPEstat prefix, AS holder, abuse contact, and PeeringDB. |
| Geolocation | Approximate city and network from ipwho.is. Not a street address and not a phone’s location. |
| InternetDB | Shodan’s free view of ports, hostnames, and listed CVEs. Footprint does not scan ports itself. |
| Malware association | Public OTX associations. A hit is not proof the host is malicious. |
| Malware URL list | URLhaus. A hit means a malware URL was reported for that host. |
| Popularity rank | Tranco rank, if the domain is on the list. |
| Green hosting | Green Web Foundation. Not a carbon audit. |

## History and mentions

| Module | What you get |
|---|---|
| Wayback Machine | Historical URLs from the Internet Archive CDX index. |
| OTX URL history | Public AlienVault URLs seen for the domain. |
| urlscan.io | Recent public submissions for the domain. |
| Public code | GitHub and GitLab repos, homepages, and issue titles. No secret scanning. |

## Identity

| Module | What you get |
|---|---|
| Public profiles | GitHub, GitLab, Mastodon, and a few other APIs that return a profile on purpose. |
| Username sites | A short Sherlock-style check: Bluesky, Reddit, Hacker News, Chess.com, Dev.to, Lemmy, and Wikipedia. A hit means the name is registered, not who operates it. The full 400-site Sherlock list is not used, because most of those sites only answer a normal browser. |
| Breach names | Breach titles from XposedOrNot. Have I Been Pwned is added when a key is saved. Categories only. |
| VirusTotal | Optional. Needs the key in Settings. |
| Numbering plan | Country, calling code, and line type for a phone number. Not a carrier lookup and not a device location. |

## Links to open

| Module | What you get |
|---|---|
| Search links | Google queries for the domain. Footprint does not fetch the result page. |
| Pivot links | Shodan, crt.sh, profile pages, and similar. For a username this includes TikTok, Pinterest, Tumblr, LinkedIn, Bluesky, and others. A link is not a confirmed account. |

## Authorized

| Module | What you get |
|---|---|
| Surface review | One homepage fetch, redirects, response headers, cookie **names and flags** (not values), social title tags, robots.txt, sitemap.xml, and security.txt. |

## Sources that were considered and left out

* **Dark web.** The usual bookmark lists are not a search API. Onion sites need Tor. Stolen-credential dumps are out of scope.
* **Live phone tracking.** Numbering-plan metadata is not a GPS fix.
* **Port scans and exploit templates.** InternetDB is a published list. Nuclei, Naabu, and similar are not run.
