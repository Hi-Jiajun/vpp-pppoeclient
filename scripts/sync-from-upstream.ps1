[CmdletBinding()]
param(
  [string]$RemoteName = "upstream",
  [string]$RemoteUrl = "https://github.com/Hi-Jiajun/vpp.git",
  [string]$Branch = "feat/pr-pppoeclient",
  [switch]$KeepTemp
)

$ErrorActionPreference = "Stop"

function Invoke-Git {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Args,
    [string]$WorkDir
  )

  if ($WorkDir) {
    & git -C $WorkDir @Args
  } else {
    & git @Args
  }

  if ($LASTEXITCODE -ne 0) {
    throw "git $($Args -join ' ') failed with exit code $LASTEXITCODE"
  }
}

function Invoke-RobocopyMirror {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Source,
    [Parameter(Mandatory = $true)]
    [string]$Destination
  )

  & robocopy $Source $Destination /MIR /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null

  if ($LASTEXITCODE -gt 7) {
    throw "robocopy failed for $Source -> $Destination with exit code $LASTEXITCODE"
  }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$pluginDirs = @(
  "src/plugins/pppoeclient",
  "src/plugins/pppox"
)

try {
  & git --version | Out-Null
} catch {
  throw "git is required but was not found in PATH"
}

$existingRemotes = @(& git -C $repoRoot remote)
if ($LASTEXITCODE -ne 0) {
  throw "failed to list git remotes"
}

if ($existingRemotes -notcontains $RemoteName) {
  Write-Host "Adding remote '$RemoteName' -> $RemoteUrl"
  Invoke-Git -Args @("remote", "add", $RemoteName, $RemoteUrl) -WorkDir $repoRoot
}

$resolvedRemoteUrl = (& git -C $repoRoot remote get-url $RemoteName).Trim()
if ($LASTEXITCODE -ne 0) {
  throw "failed to resolve URL for remote '$RemoteName'"
}

Write-Host "Fetching $RemoteName/$Branch ..."
Invoke-Git -Args @("fetch", $RemoteName, $Branch) -WorkDir $repoRoot

$tempClone = Join-Path ([System.IO.Path]::GetTempPath()) ("vpp-plugin-sync-" + [guid]::NewGuid().ToString())

try {
  Write-Host "Creating sparse clone in $tempClone"
  Invoke-Git -Args @("clone", "--depth", "1", "--filter=blob:none", "--sparse", "--branch", $Branch, $resolvedRemoteUrl, $tempClone)

  Write-Host "Checking out plugin directories only"
  $sparseArgs = @("sparse-checkout", "set") + $pluginDirs
  Invoke-Git -Args $sparseArgs -WorkDir $tempClone

  foreach ($dir in $pluginDirs) {
    $source = Join-Path $tempClone $dir
    $destination = Join-Path $repoRoot $dir

    Write-Host "Syncing $dir"
    Invoke-RobocopyMirror -Source $source -Destination $destination
  }

  $upstreamCommit = (& git -C $tempClone rev-parse HEAD).Trim()
  if ($LASTEXITCODE -ne 0) {
    throw "failed to read upstream commit"
  }

  Write-Host ""
  Write-Host "Sync complete."
  Write-Host "Upstream branch: $Branch"
  Write-Host "Upstream commit: $upstreamCommit"
  Write-Host ""
  Write-Host "Next suggested commands:"
  Write-Host "  git status --short"
  Write-Host "  git diff --stat"
} finally {
  if (-not $KeepTemp -and (Test-Path $tempClone)) {
    Remove-Item -Recurse -Force $tempClone
  }
}
