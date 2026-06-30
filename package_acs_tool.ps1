param(
    [string]$ProjectRoot = (Split-Path -Parent $PSCommandPath),
    [string]$TargetDir = (Join-Path ([Environment]::GetFolderPath("Desktop")) "ACS Tool"),
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [ValidateSet("stable", "testing")]
    [string]$Channel = "stable",
    [string]$VersionLabel = "",
    [string]$ArtifactDir = "",
    [switch]$SkipZip
)

$ErrorActionPreference = "Stop"

function Require-Path {
    param(
        [string]$PathValue,
        [string]$Label
    )

    if (-not (Test-Path -LiteralPath $PathValue)) {
        throw "$Label not found: $PathValue"
    }
}

function Copy-FirstAvailableFile {
    param(
        [string[]]$Candidates,
        [string]$DestinationDir,
        [string]$Label
    )

    foreach ($candidate in $Candidates) {
        if (Test-Path -LiteralPath $candidate) {
            Copy-Item -LiteralPath $candidate -Destination $DestinationDir -Force
            Write-Host "Copied $Label from $candidate"
            return
        }
    }

    throw "Could not locate $Label. Checked: $($Candidates -join ', ')"
}

function Resolve-FirstExistingPath {
    param(
        [string[]]$Candidates,
        [string]$Label
    )

    foreach ($candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    throw "$Label not found. Checked: $($Candidates -join ', ')"
}

function Resolve-LatestMatchingPath {
    param(
        [string]$Pattern,
        [string]$Label
    )

    $matches = Get-ChildItem -Path $Pattern -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
    if ($matches -and $matches.Count -gt 0) {
        return $matches[0].FullName
    }

    throw "$Label not found with pattern: $Pattern"
}

function New-ZipArtifact {
    param(
        [string]$SourceDir,
        [string]$ZipPath
    )

    if (Test-Path -LiteralPath $ZipPath) {
        Remove-Item -LiteralPath $ZipPath -Force
    }

    Compress-Archive -Path (Join-Path $SourceDir '*') -DestinationPath $ZipPath -CompressionLevel Optimal
}

function Write-ChecksumFile {
    param(
        [string]$FilePath,
        [string]$ChecksumPath
    )

    $hash = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $fileName = Split-Path -Leaf $FilePath
    Set-Content -LiteralPath $ChecksumPath -Value "$hash  $fileName" -Encoding ASCII
    return $hash
}

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$msbuild = if (Test-Path -LiteralPath $vswhere) {
    $installPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($installPath)) {
        Join-Path $installPath "MSBuild\Current\Bin\amd64\MSBuild.exe"
    }
}
if (-not $msbuild) {
    $msbuild = Resolve-FirstExistingPath -Candidates @(
        "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\17\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
    ) -Label "MSBuild"
}

$qtRoot = if ($env:QTDIR) { $env:QTDIR }
$windeployqt = if ($qtRoot) {
    Join-Path $qtRoot "bin\windeployqt.exe"
}
if (-not $windeployqt -or -not (Test-Path -LiteralPath $windeployqt)) {
    $windeployqt = Resolve-LatestMatchingPath -Pattern "C:\Qt\*\msvc*\bin\windeployqt.exe" -Label "windeployqt"
}

$solution = Join-Path $ProjectRoot "ACS_Wynn_Builder.vcxproj"
$buildOutputDir = Join-Path $ProjectRoot "$Platform\$Configuration"
$exePath = Join-Path $buildOutputDir "ACS_Wynn_Builder.exe"
$localDependencyDir = Join-Path $ProjectRoot "third_party\libssh\bin"
$localDeployDir = Join-Path ([Environment]::GetFolderPath("Desktop")) "ACS Deploy"
$vcRedistDir = Resolve-LatestMatchingPath -Pattern "C:\Program Files\Microsoft Visual Studio\*\*\VC\Redist\MSVC\*\x64\Microsoft.VC*.CRT" -Label "VC++ runtime directory"
$stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ACS_Tool_Package"
$stagingDir = Join-Path $stagingRoot ([Guid]::NewGuid().ToString("N"))
$effectiveArtifactDir = if (-not [string]::IsNullOrWhiteSpace($ArtifactDir)) {
    $ArtifactDir
} else {
    Join-Path $ProjectRoot ("dist\artifacts\" + $Channel)
}

Require-Path -PathValue $msbuild -Label "MSBuild"
Require-Path -PathValue $windeployqt -Label "windeployqt"
Require-Path -PathValue $solution -Label "Project file"

Write-Host "Building $solution ($Configuration|$Platform)..."
& $msbuild $solution "/p:Configuration=$Configuration" "/p:Platform=$Platform"
if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE"
}

Require-Path -PathValue $exePath -Label "Built executable"

New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

Copy-Item -LiteralPath $exePath -Destination $stagingDir -Force

Write-Host "Running windeployqt..."
& $windeployqt --release --compiler-runtime --no-translations (Join-Path $stagingDir "ACS_Wynn_Builder.exe")
if ($LASTEXITCODE -ne 0) {
    throw "windeployqt failed with exit code $LASTEXITCODE"
}

$sshCandidates = @{
    "ssh.dll" = @(
        (Join-Path $localDependencyDir "ssh.dll"),
        (Join-Path $ProjectRoot "ssh.dll"),
        (Join-Path $localDeployDir "ssh.dll")
    )
    "libcrypto-3-x64.dll" = @(
        (Join-Path $localDependencyDir "libcrypto-3-x64.dll"),
        (Join-Path $ProjectRoot "libcrypto-3-x64.dll"),
        (Join-Path $buildOutputDir "libcrypto-3-x64.dll"),
        (Join-Path $localDeployDir "libcrypto-3-x64.dll")
    )
    "libssl-3-x64.dll" = @(
        (Join-Path $localDependencyDir "libssl-3-x64.dll"),
        (Join-Path $ProjectRoot "libssl-3-x64.dll"),
        (Join-Path $buildOutputDir "libssl-3-x64.dll"),
        (Join-Path $localDeployDir "libssl-3-x64.dll")
    )
}

foreach ($entry in $sshCandidates.GetEnumerator()) {
    Copy-FirstAvailableFile -Candidates $entry.Value -DestinationDir $stagingDir -Label $entry.Key
}

$runtimeFiles = @(
    "msvcp140.dll",
    "msvcp140_1.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll"
)

foreach ($runtimeFile in $runtimeFiles) {
    Copy-Item -LiteralPath (Join-Path $vcRedistDir $runtimeFile) -Destination $stagingDir -Force
}

$configCandidates = @(
    (Join-Path $ProjectRoot "ap_groups.json"),
    (Join-Path $buildOutputDir "ap_groups.json"),
    (Join-Path (Split-Path $ProjectRoot -Parent) "$Platform\$Configuration\ap_groups.json")
)

foreach ($configCandidate in $configCandidates) {
    if (Test-Path -LiteralPath $configCandidate) {
        Copy-Item -LiteralPath $configCandidate -Destination $stagingDir -Force
        Write-Host "Copied ap_groups.json from $configCandidate"
        break
    }
}

$headerPath = Join-Path $ProjectRoot "ACS_Wynn_Builder.h"
$effectiveVersion = ""
if (Test-Path -LiteralPath $headerPath) {
    $versionMatch = Select-String -Path $headerPath -Pattern 'CURRENT_VERSION\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($versionMatch -and $versionMatch.Matches.Count -gt 0) {
        $currentVersion = $versionMatch.Matches[0].Groups[1].Value
        $effectiveVersion = if (-not [string]::IsNullOrWhiteSpace($VersionLabel)) {
            $VersionLabel.Trim()
        } elseif ($Channel -eq "testing") {
            "$currentVersion-testing"
        } else {
            $currentVersion
        }

        Set-Content -LiteralPath (Join-Path $stagingDir "version.txt") -Value $effectiveVersion -Encoding ASCII
        Write-Host "Wrote version.txt ($effectiveVersion) for channel '$Channel'"
    }
}

if (Test-Path -LiteralPath $TargetDir) {
    try {
        Remove-Item -LiteralPath $TargetDir -Recurse -Force
    }
    catch {
        throw "Could not replace '$TargetDir'. Close any running copy of ACS Tool and try again. Details: $($_.Exception.Message)"
    }
}

Move-Item -LiteralPath $stagingDir -Destination $TargetDir

if (-not $SkipZip) {
    if ([string]::IsNullOrWhiteSpace($effectiveVersion)) {
        throw "Could not determine the package version label for zip artifact generation."
    }

    New-Item -ItemType Directory -Path $effectiveArtifactDir -Force | Out-Null

    $versionedBaseName = "ACS_Wynn_Builder_Update_{0}" -f $effectiveVersion
    $versionedZipPath = Join-Path $effectiveArtifactDir ($versionedBaseName + ".zip")
    $versionedShaPath = Join-Path $effectiveArtifactDir ($versionedBaseName + ".sha256")
    $latestZipPath = Join-Path $effectiveArtifactDir "ACS_Wynn_Builder_Update.zip"
    $latestShaPath = Join-Path $effectiveArtifactDir "ACS_Wynn_Builder_Update.sha256"

    New-ZipArtifact -SourceDir $TargetDir -ZipPath $versionedZipPath
    $versionedHash = Write-ChecksumFile -FilePath $versionedZipPath -ChecksumPath $versionedShaPath
    Copy-Item -LiteralPath $versionedZipPath -Destination $latestZipPath -Force
    Set-Content -LiteralPath $latestShaPath -Value "$versionedHash  $(Split-Path -Leaf $latestZipPath)" -Encoding ASCII
}

Write-Host ""
Write-Host "ACS Tool package created:"
Write-Host "  $TargetDir"
if (-not $SkipZip) {
    Write-Host "GitHub-ready artifacts:"
    Write-Host "  $effectiveArtifactDir"
    Write-Host "Upload these files to GitHub for the '$Channel' channel:"
    Write-Host "  $(Join-Path $effectiveArtifactDir 'ACS_Wynn_Builder_Update.zip')"
    Write-Host "  $(Join-Path $effectiveArtifactDir 'ACS_Wynn_Builder_Update.sha256')"
}
Write-Host ""
Get-ChildItem -LiteralPath $TargetDir | Sort-Object Name | Select-Object Name, Length, LastWriteTime
