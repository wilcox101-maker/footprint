# Save this file anywhere and run:
#   powershell -ExecutionPolicy Bypass -File .\Start-Footprint.ps1
# Nothing else has to be installed. The script downloads Node, downloads
# wilcox101-maker/footprint, installs packages, and opens the app.

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Owner = "wilcox101-maker"
$Repo = "footprint"
$Branch = "main"
$NodeVersion = "22.23.3"
$Root = Join-Path $env:LOCALAPPDATA "Footprint"
$NodeHome = Join-Path $Root "runtime\node-v$NodeVersion-win-x64"
$NodeExe = Join-Path $NodeHome "node.exe"
$Npm = Join-Path $NodeHome "npm.cmd"
$TokenFile = Join-Path $Root "github.token"
$App = Join-Path $Root "app"
$ShaFile = Join-Path $Root "source.sha"
$Page = "http://127.0.0.1:8080/"

function Test-Listen {
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect("127.0.0.1", 8080)
    $client.Close()
    return $true
  } catch {
    return $false
  }
}

function Read-Token {
  if (Test-Path $TokenFile) {
    $saved = (Get-Content -Path $TokenFile -Raw).Trim()
    if ($saved) { return $saved }
  }
  Write-Host ""
  Write-Host "Footprint's GitHub repo is private. Paste a token that can read $Owner/$Repo."
  Write-Host "GitHub, Settings, Developer settings, Personal access tokens. Contents: Read is enough."
  $secure = Read-Host "GitHub token" -AsSecureString
  $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  try {
    $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
  }
  $value = $value.Trim()
  if (-not $value) { throw "No token entered." }
  New-Item -ItemType Directory -Force -Path $Root | Out-Null
  Set-Content -Path $TokenFile -Value $value -NoNewline
  return $value
}

function Get-GithubHeaders {
  $headers = @{
    Accept                 = "application/vnd.github+json"
    "User-Agent"           = "Footprint-launcher"
    "X-GitHub-Api-Version" = "2022-11-28"
  }
  if ($script:Token) { $headers.Authorization = "Bearer $script:Token" }
  return $headers
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null

if (-not (Test-Path $NodeExe)) {
  Write-Host "Downloading Node.js $NodeVersion ..."
  $zip = Join-Path $env:TEMP "node-v$NodeVersion-win-x64.zip"
  Invoke-WebRequest -Uri "https://nodejs.org/dist/v$NodeVersion/node-v$NodeVersion-win-x64.zip" -OutFile $zip
  New-Item -ItemType Directory -Force -Path (Join-Path $Root "runtime") | Out-Null
  Expand-Archive -Path $zip -DestinationPath (Join-Path $Root "runtime") -Force
  Remove-Item $zip -Force
}

$script:Token = ""
if (Test-Path $TokenFile) { $script:Token = (Get-Content -Path $TokenFile -Raw).Trim() }
$headers = Get-GithubHeaders

try {
  $commit = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$Owner/$Repo/commits/$Branch"
} catch {
  if (Test-Path $TokenFile) { Remove-Item $TokenFile -Force -ErrorAction SilentlyContinue }
  $script:Token = Read-Token
  $headers = Get-GithubHeaders
  try {
    $commit = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$Owner/$Repo/commits/$Branch"
  } catch {
    if (Test-Path $TokenFile) { Remove-Item $TokenFile -Force -ErrorAction SilentlyContinue }
    throw "GitHub refused the download. If the repo is private again, run the script and paste a token that can read $Owner/$Repo."
  }
}

$sha = $commit.sha
$have = ""
if (Test-Path $ShaFile) { $have = (Get-Content -Path $ShaFile -Raw).Trim() }

if ($sha -ne $have -or -not (Test-Path (Join-Path $App "package.json"))) {
  if (Test-Listen) {
    Write-Host "A newer copy is on GitHub, but Footprint is already running. Close it, then run this script again."
    Start-Process $Page
    exit 0
  }
  Write-Host "Downloading $Owner/$Repo ($($sha.Substring(0, 7))) ..."
  $zip = Join-Path $env:TEMP "footprint-src.zip"
  Invoke-WebRequest -Headers $headers -Uri "https://api.github.com/repos/$Owner/$Repo/zipball/$Branch" -OutFile $zip
  $staging = Join-Path $Root "staging"
  if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
  Expand-Archive -Path $zip -DestinationPath $staging -Force
  Remove-Item $zip -Force
  $extracted = Get-ChildItem -Path $staging -Directory | Select-Object -First 1
  if (-not $extracted) { throw "The GitHub download did not contain the project." }

  $oldModules = Join-Path $App "node_modules"
  $keptModules = Join-Path $Root "node_modules.keep"
  if (Test-Path $keptModules) { Remove-Item $keptModules -Recurse -Force }
  $oldLock = Join-Path $App "package-lock.json"
  $newLock = Join-Path $extracted.FullName "package-lock.json"
  $sameLock = $false
  if ((Test-Path $oldLock) -and (Test-Path $newLock) -and (Test-Path $oldModules)) {
    $sameLock = (Get-FileHash $oldLock).Hash -eq (Get-FileHash $newLock).Hash
    if ($sameLock) { Move-Item $oldModules $keptModules }
  }
  if (Test-Path $App) { Remove-Item $App -Recurse -Force }
  Move-Item $extracted.FullName $App
  if ($sameLock) { Move-Item $keptModules (Join-Path $App "node_modules") }
  Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
  Set-Content -Path $ShaFile -Value $sha -NoNewline
  Write-Host "Project is at $App"
}

$env:Path = "$NodeHome;" + $env:Path
if (-not (Test-Path (Join-Path $App "node_modules"))) {
  Write-Host "Installing packages ..."
  & $Npm install --prefix $App
  if ($LASTEXITCODE -ne 0) { throw "npm install failed." }
}

if (Test-Listen) {
  Write-Host "Footprint is already running at $Page"
  Start-Process $Page
  exit 0
}

Write-Host "Starting Footprint at $Page"
$proc = Start-Process -FilePath $Npm -ArgumentList @("run", "dev") -WorkingDirectory $App -PassThru -WindowStyle Hidden
$deadline = (Get-Date).AddMinutes(3)
$up = $false
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { throw "The app stopped before it opened." }
  if (Test-Listen) { $up = $true; break }
  Start-Sleep -Seconds 1
}
if (-not $up) {
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
  throw "Footprint did not open on port 8080."
}

Start-Process $Page
Write-Host "Leave this window open. Close it to stop Footprint."
try {
  Wait-Process -Id $proc.Id
} finally {
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}
