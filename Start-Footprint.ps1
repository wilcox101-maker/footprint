# From a normal PowerShell window:
#   irm "https://raw.githubusercontent.com/wilcox101-maker/footprint/main/win.ps1?v=5" | iex
# Nothing else has to be installed. The script downloads Node, downloads
# wilcox101-maker/footprint, installs packages, and opens the app.

Write-Host "Footprint launcher 5"

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not ('Footprint.NativePath' -as [type])) {
  Add-Type -Namespace Footprint -Name NativePath -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
public static extern uint GetLongPathName(string shortPath, System.Text.StringBuilder longPath, uint buffer);
'@
}

# $env:TEMP on this PC is an 8.3 path (C:\Users\D8EF9~1.WIL\...). PowerShell
# treats the tilde as a wildcard. Always use the current user's long profile.
function ConvertTo-LongPath([string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
  $buffer = New-Object System.Text.StringBuilder 1024
  $n = [Footprint.NativePath]::GetLongPathName($Path, $buffer, [uint32]$buffer.Capacity)
  if ($n -gt 0 -and $n -lt $buffer.Capacity) { return $buffer.ToString() }
  return $Path
}

function Remove-Exact([string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  if ([System.IO.Directory]::Exists($Path)) { [System.IO.Directory]::Delete($Path, $true) }
  elseif ([System.IO.File]::Exists($Path)) { [System.IO.File]::Delete($Path) }
}

$UserHome = ConvertTo-LongPath ([Environment]::GetFolderPath('UserProfile'))
if (-not $UserHome) { $UserHome = ConvertTo-LongPath $env:USERPROFILE }
$Local = Join-Path $UserHome "AppData\Local"
$Root = Join-Path $Local "Footprint"
$WorkTemp = Join-Path $Local "Temp"
$Owner = "wilcox101-maker"
$Repo = "footprint"
$Branch = "main"
$NodeVersion = "22.23.3"
$NodeHome = Join-Path $Root "runtime\node-v${NodeVersion}-win-x64"
$NodeExe = Join-Path $NodeHome "node.exe"
$Npm = Join-Path $NodeHome "npm.cmd"
$TokenFile = Join-Path $Root "github.token"
$App = Join-Path $Root "app"
$ShaFile = Join-Path $Root "source.sha"
$Page = "http://127.0.0.1:8080/"

Write-Host "Running as $env:USERNAME"
Write-Host "Files go in $Root"

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
  if (Test-Path -LiteralPath $TokenFile) {
    $saved = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
    if ($saved) { return $saved }
  }
  Write-Host ""
  Write-Host "GitHub refused the download. Paste a token that can read $Owner/$Repo."
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
  Set-Content -LiteralPath $TokenFile -Value $value -NoNewline
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

New-Item -ItemType Directory -Force -Path $Root, $WorkTemp | Out-Null

if (-not (Test-Path -LiteralPath $NodeExe)) {
  Write-Host "Downloading Node.js $NodeVersion ..."
  $zip = Join-Path $WorkTemp "node-v${NodeVersion}-win-x64.zip"
  Invoke-WebRequest -Uri "https://nodejs.org/dist/v${NodeVersion}/node-v${NodeVersion}-win-x64.zip" -OutFile $zip
  New-Item -ItemType Directory -Force -Path (Join-Path $Root "runtime") | Out-Null
  Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $Root "runtime") -Force
  Remove-Exact $zip
}

$script:Token = ""
if (Test-Path -LiteralPath $TokenFile) { $script:Token = (Get-Content -LiteralPath $TokenFile -Raw).Trim() }
$headers = Get-GithubHeaders

try {
  $commit = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$Owner/$Repo/commits/$Branch"
} catch {
  Remove-Exact $TokenFile
  $script:Token = Read-Token
  $headers = Get-GithubHeaders
  try {
    $commit = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$Owner/$Repo/commits/$Branch"
  } catch {
    Remove-Exact $TokenFile
    throw "GitHub refused the download. If the repo is private again, run the script and paste a token that can read $Owner/$Repo."
  }
}

$sha = $commit.sha
$have = ""
if (Test-Path -LiteralPath $ShaFile) { $have = (Get-Content -LiteralPath $ShaFile -Raw).Trim() }

if ($sha -ne $have -or -not (Test-Path -LiteralPath (Join-Path $App "package.json"))) {
  if (Test-Listen) {
    Write-Host "A newer copy is on GitHub, but Footprint is already running. Close it, then run this script again."
    Start-Process $Page
    exit 0
  }
  Write-Host "Downloading $Owner/$Repo ($($sha.Substring(0, 7))) ..."
  $zip = Join-Path $WorkTemp "footprint-src.zip"
  Invoke-WebRequest -Headers $headers -Uri "https://api.github.com/repos/$Owner/$Repo/zipball/$Branch" -OutFile $zip
  $staging = Join-Path $Root "staging"
  Remove-Exact $staging
  Expand-Archive -LiteralPath $zip -DestinationPath $staging -Force
  Remove-Exact $zip
  $extracted = Get-ChildItem -LiteralPath $staging -Directory | Select-Object -First 1
  if (-not $extracted) { throw "The GitHub download did not contain the project." }

  $oldModules = Join-Path $App "node_modules"
  $keptModules = Join-Path $Root "node_modules.keep"
  Remove-Exact $keptModules
  $oldLock = Join-Path $App "package-lock.json"
  $newLock = Join-Path $extracted.FullName "package-lock.json"
  $sameLock = $false
  if ((Test-Path -LiteralPath $oldLock) -and (Test-Path -LiteralPath $newLock) -and (Test-Path -LiteralPath $oldModules)) {
    $sameLock = (Get-FileHash -LiteralPath $oldLock).Hash -eq (Get-FileHash -LiteralPath $newLock).Hash
    if ($sameLock) { Move-Item -LiteralPath $oldModules -Destination $keptModules }
  }
  Remove-Exact $App
  Move-Item -LiteralPath $extracted.FullName -Destination $App
  if ($sameLock) { Move-Item -LiteralPath $keptModules -Destination (Join-Path $App "node_modules") }
  Remove-Exact $staging
  Set-Content -LiteralPath $ShaFile -Value $sha -NoNewline
  Write-Host "Project is at $App"
}

Set-Location -LiteralPath $App
$env:Path = "$NodeHome;" + $env:Path
if (-not (Test-Path -LiteralPath (Join-Path $App "node_modules"))) {
  Write-Host "Installing packages ..."
  & $Npm install
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
