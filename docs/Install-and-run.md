# Install and run

You need Node.js and npm. The app is a TypeScript web project. There is no separate database to install.

```bash
git clone https://github.com/wilcox101-maker/footprint.git
cd footprint
npm install
npm run dev
```

Open the address the dev server prints. Scans you start are stored in that browser.

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
