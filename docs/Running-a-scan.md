# Running a scan

On the home page, type a target. Footprint guesses the kind:

| You type | Kind |
|---|---|
| `example.com` | Domain |
| `https://example.com/path` | URL |
| `name@example.com` | Email |
| `ada` | Username |
| `+16165550100` or a digits-only number | Phone |
| A public IPv4 or IPv6 address | IP |

Private, loopback, and link-local addresses are refused. A username is 2–39 letters, numbers, underscores, or hyphens.

Pick a preset or turn modules on and off. **Start scan** opens an investigation and runs the modules you left checked.

## Presets

| Preset | Use it for |
|---|---|
| Passive domain sweep | Certificates, DNS, mail, routing, archives, blocklist, DNSSEC, green hosting, and links. |
| Username footprint | Profile APIs, the short username-site check, public code, and links. |
| Email and breach names | Breach titles, mail posture, public code. No passwords. |
| IP intelligence | Registration, routing, geolocation, passive DNS, InternetDB, malware association, URLhaus. |
| Authorized surface review | Homepage, robots.txt, sitemap, and security.txt. You must confirm you are allowed to request that site. |
| Phone numbering plan | Country and line type only, plus search links. |

## While it runs

Modules run one after another. A failure in one source does not cancel the rest. When the bar says Completed, the counts are final for that run.

## Again later

A monitor on an investigation reruns the same modules while this browser has Footprint open. There is no cloud scheduler. If the tab is closed, the schedule does not fire.

Date range on the investigation limits charts, the report, and cleanup of old rows. It does not delete the live site.
