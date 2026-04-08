param(
    [string]$RepoRoot = "D:\DSE\DesignSpaceExplorationforSecurity-main\DesignSpaceExplorationforSecurity-main",
    [string]$OutputZip = ""
)

$ErrorActionPreference = "Stop"

$resolvedRepo = (Resolve-Path -LiteralPath $RepoRoot).Path
if (-not $OutputZip) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputZip = Join-Path $resolvedRepo "DSE_Core\tools\dse_core_colab_repo_$stamp.zip"
}

$outputDir = Split-Path -Parent $OutputZip
if (-not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

if (Test-Path -LiteralPath $OutputZip) {
    Remove-Item -LiteralPath $OutputZip -Force
}

$excludePatterns = @(
    "\\.git\\",
    "\\.pytest_cache\\",
    "\\.mypy_cache\\",
    "\\__pycache__\\",
    "\\.venv\\",
    "\\.idea\\",
    "\\.vs\\"
)

$files = Get-ChildItem -LiteralPath $resolvedRepo -Recurse -File | Where-Object {
    $full = $_.FullName
    foreach ($pattern in $excludePatterns) {
        if ($full -match $pattern) {
            return $false
        }
    }
    return $true
}

Compress-Archive -LiteralPath $files.FullName -DestinationPath $OutputZip -CompressionLevel Optimal

$zipInfo = Get-Item -LiteralPath $OutputZip
[pscustomobject]@{
    RepoRoot = $resolvedRepo
    OutputZip = $zipInfo.FullName
    SizeMB = [math]::Round($zipInfo.Length / 1MB, 2)
    FileCount = $files.Count
} | Format-List
