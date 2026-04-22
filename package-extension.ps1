param(
  [string]$OutputPath = "dist/total-sense-extension.zip"
)

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$resolvedOutputPath = Join-Path $repoRoot $OutputPath
$outputDirectory = Split-Path -Parent $resolvedOutputPath

if (-not (Test-Path -LiteralPath $outputDirectory)) {
  New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

if (Test-Path -LiteralPath $resolvedOutputPath) {
  Remove-Item -LiteralPath $resolvedOutputPath -Force
}

$itemsToArchive = @(
  (Join-Path $repoRoot "manifest.json"),
  (Join-Path $repoRoot "fonts.css"),
  (Join-Path $repoRoot "popup.html"),
  (Join-Path $repoRoot "popup.css"),
  (Join-Path $repoRoot "popup.js"),
  (Join-Path $repoRoot "options.html"),
  (Join-Path $repoRoot "options.css"),
  (Join-Path $repoRoot "options.js"),
  (Join-Path $repoRoot "assets"),
  (Join-Path $repoRoot "lib")
)

Compress-Archive -Path $itemsToArchive -DestinationPath $resolvedOutputPath -Force

Write-Output "Created $resolvedOutputPath"
