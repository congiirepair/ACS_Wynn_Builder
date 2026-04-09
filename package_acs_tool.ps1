param(
    [string]$ProjectRoot = "C:\Users\congi\source\repos\ACS_Wynn_Builder\ACS_Wynn_Builder",
    [string]$TargetDir = "C:\Users\congi\Desktop\ACS Tool",
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
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

$msbuild = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
$windeployqt = "C:\Qt\6.11.0\msvc2022_64\bin\windeployqt.exe"
$solution = Join-Path $ProjectRoot "ACS_Wynn_Builder.vcxproj"
$buildOutputDir = Join-Path $ProjectRoot "$Platform\$Configuration"
$exePath = Join-Path $buildOutputDir "ACS_Wynn_Builder.exe"
$localDependencyDir = Join-Path $ProjectRoot "third_party\libssh\bin"
$localDeployDir = "C:\Users\congi\Desktop\ACS Deploy"
$vcRedistDir = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Redist\MSVC\14.50.35710\x64\Microsoft.VC145.CRT"

Require-Path -PathValue $msbuild -Label "MSBuild"
Require-Path -PathValue $windeployqt -Label "windeployqt"
Require-Path -PathValue $solution -Label "Project file"

Write-Host "Building $solution ($Configuration|$Platform)..."
& $msbuild $solution "/p:Configuration=$Configuration" "/p:Platform=$Platform"
if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE"
}

Require-Path -PathValue $exePath -Label "Built executable"

if (Test-Path -LiteralPath $TargetDir) {
    Remove-Item -LiteralPath $TargetDir -Recurse -Force
}
New-Item -ItemType Directory -Path $TargetDir | Out-Null

Copy-Item -LiteralPath $exePath -Destination $TargetDir -Force

Write-Host "Running windeployqt..."
& $windeployqt --release --compiler-runtime --no-translations (Join-Path $TargetDir "ACS_Wynn_Builder.exe")
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
    Copy-FirstAvailableFile -Candidates $entry.Value -DestinationDir $TargetDir -Label $entry.Key
}

Require-Path -PathValue $vcRedistDir -Label "VC++ runtime directory"

$runtimeFiles = @(
    "msvcp140.dll",
    "msvcp140_1.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll"
)

foreach ($runtimeFile in $runtimeFiles) {
    Copy-Item -LiteralPath (Join-Path $vcRedistDir $runtimeFile) -Destination $TargetDir -Force
}

$configCandidates = @(
    (Join-Path $ProjectRoot "ap_groups.json"),
    (Join-Path $buildOutputDir "ap_groups.json"),
    (Join-Path (Split-Path $ProjectRoot -Parent) "$Platform\$Configuration\ap_groups.json")
)

foreach ($configCandidate in $configCandidates) {
    if (Test-Path -LiteralPath $configCandidate) {
        Copy-Item -LiteralPath $configCandidate -Destination $TargetDir -Force
        Write-Host "Copied ap_groups.json from $configCandidate"
        break
    }
}

Write-Host ""
Write-Host "ACS Tool package created:"
Write-Host "  $TargetDir"
Write-Host ""
Get-ChildItem -LiteralPath $TargetDir | Sort-Object Name | Select-Object Name, Length, LastWriteTime
