# Install and run

You need Node.js and npm. The app is a TypeScript web project. There is no separate database to install.

```bash
git clone https://github.com/wilcox101-maker/footprint.git
cd footprint
npm install
npm run dev
```

Open the address the dev server prints. Scans you start are stored in that browser.

## Windows, one script, no prior download

Save `Start-Footprint.ps1` anywhere. You do not need Git, Node, or a clone already on the machine.

```powershell
powershell -ExecutionPolicy Bypass -File .\Start-Footprint.ps1
```

The script then:

1. Downloads Node.js into `%LOCALAPPDATA%\Footprint\runtime` if it is not there.
2. Downloads `wilcox101-maker/footprint` from GitHub. The repo is private, so the first run asks for a personal access token with read access to the repository. The token is stored at `%LOCALAPPDATA%\Footprint\github.token` and is only sent to GitHub.
3. Installs packages when `package-lock.json` changes.
4. Starts the app and opens the browser.

The next run reuses Node and the download. If the app is already open, the script only focuses the browser. Close it and run the script again to pick up a newer commit.

Internet is required the first time, and whenever a lookup runs. Investigations stay in the browser, not in the script.

## Other commands

| Command | What it does |
|---|---|
| `npm run typecheck` | Typecheck only. Does not start the app. |
| `npm run build` | Production build, then the local database migration the scaffold expects. |
| `npm test` | The scaffold’s unit tests. |

A production build is for hosting the interface. The investigation data still lives in the browser, not in that build.

## Optional keys

Settings can hold a Have I Been Pwned key and a VirusTotal key. Leave both blank and those two lookups are skipped or limited to sources that do not need a key. Breach titles still come from XposedOrNot without a key. The keys stay in this browser. They are sent only when you start a lookup that needs them, and only to that vendor.

## Updating

```bash
git pull
npm install
npm run dev
```
