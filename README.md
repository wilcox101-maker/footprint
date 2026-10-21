# Footprint

Local digital-footprint scans from public sources. Findings stay in this browser.

A scan reports a risk level, breach titles, public profiles, published registration contacts, and how to take a listing down. It does not collect password values, national identity numbers, or dump contents.

```bash
npm install
npm run dev
```

On a Windows PC with nothing else installed, save [Start-Footprint.ps1](Start-Footprint.ps1) and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\Start-Footprint.ps1
```

The script downloads Node.js, downloads this repo, installs packages, and opens the app. No GitHub token is required while the repo is public. Scans still stay in the browser.

Open the app, enter a domain, email, username, phone number, or public IP you are allowed to research, and start a scan.

Open the app, enter a domain, email, username, phone number, or public IP you are allowed to research, and start a scan.

The write-up is in [docs/Home.md](docs/Home.md): how to run a scan, what each module returns, how to read the risk counts, and how to ask a site to take a listing down.

