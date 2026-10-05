$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$env:GOCACHE = Join-Path $env:TEMP 'vpswall-go-cache'
$env:GOTMPDIR = Join-Path $env:TEMP 'vpswall-go-tmp'
New-Item -ItemType Directory -Force -Path $env:GOTMPDIR | Out-Null
function Invoke-Go {
    param([string[]]$Arguments)
    & go @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Go command failed.' }
}
Invoke-Go @('test', '-v', './...')
Invoke-Go @('vet', './...')
New-Item -ItemType Directory -Force -Path 'dist' | Out-Null
$taskPreviousGOOS = $env:GOOS
$taskPreviousGOARCH = $env:GOARCH
$taskPreviousCGO = $env:CGO_ENABLED
try {
    $env:GOOS = 'linux'
    $env:CGO_ENABLED = '0'
    foreach ($taskArch in @('amd64', 'arm64')) {
        $env:GOARCH = $taskArch
        Invoke-Go @('build', '-trimpath', '-ldflags=-s -w', '-o', "dist/vpswall-linux-$taskArch", '.')
    }
} finally {
    $env:GOOS = $taskPreviousGOOS
    $env:GOARCH = $taskPreviousGOARCH
    $env:CGO_ENABLED = $taskPreviousCGO
}
$taskArchive = Join-Path $PSScriptRoot 'vpswall-0.2.0.zip'
$taskFiles = @('go.mod', 'go.sum', 'README.md', 'install.sh', 'build.ps1', 'THIRD_PARTY_NOTICES.txt', 'dist') + @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.go' -File | ForEach-Object { $_.Name }) + @('tests/linux-lab.sh', 'tests/linux-lab-inner.sh')
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
if (Test-Path -LiteralPath $taskArchive) { Remove-Item -LiteralPath $taskArchive }
$taskZip = [IO.Compression.ZipFile]::Open($taskArchive, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($taskFile in $taskFiles) {
        if ($taskFile -eq 'dist') {
            foreach ($taskBinary in @('vpswall-linux-amd64', 'vpswall-linux-arm64')) {
                $taskBinaryPath = Join-Path (Join-Path $PSScriptRoot 'dist') $taskBinary
                [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($taskZip, $taskBinaryPath, "dist/$taskBinary", [IO.Compression.CompressionLevel]::Optimal)
            }
        } else {
            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($taskZip, (Join-Path $PSScriptRoot $taskFile), $taskFile, [IO.Compression.CompressionLevel]::Optimal)
        }
    }
} finally {
    $taskZip.Dispose()
}
$taskHashLines = @('dist/vpswall-linux-amd64', 'dist/vpswall-linux-arm64', 'vpswall-0.2.0.zip') | ForEach-Object {
    $taskHash = Get-FileHash -Algorithm SHA256 -LiteralPath $_
    $taskHash.Hash.ToLowerInvariant() + '  ' + $_
}
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'SHA256SUMS.txt'), (($taskHashLines -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
Write-Host "Built: $taskArchive"