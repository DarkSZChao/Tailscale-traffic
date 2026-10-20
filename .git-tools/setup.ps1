$ErrorActionPreference = 'Stop'

$repoRoot = git -C (Join-Path $PSScriptRoot '..') rev-parse --show-toplevel
if ($LASTEXITCODE -ne 0) { throw 'Cannot locate the Git repository.' }

# Keep Git path matching case-sensitive inside this repository.
# This is important on Windows/macOS when files differ only by case.
git -C $repoRoot config --local core.ignorecase false
if ($LASTEXITCODE -ne 0) { throw 'Cannot set core.ignorecase.' }
git -C $repoRoot config --local core.hooksPath '.git-tools/hooks'
if ($LASTEXITCODE -ne 0) { throw 'Cannot set core.hooksPath.' }

Write-Host "Repository [$repoRoot] configured."
Write-Host 'core.ignorecase = false'
Write-Host 'core.hooksPath = .git-tools/hooks'
