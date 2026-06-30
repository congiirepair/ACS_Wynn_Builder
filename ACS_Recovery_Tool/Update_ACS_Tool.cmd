@echo off
setlocal EnableExtensions

set "REPOSITORY=congiirepair/ACS_Wynn_Builder"
set "ASSET_NAME=ACS_Wynn_Builder_Update.zip"
set "TEMP_ROOT=%TEMP%\ACS_Tool_Updater"
set "ZIP_PATH=%TEMP_ROOT%\%ASSET_NAME%"
set "EXTRACT_PATH=%TEMP_ROOT%\extract"
set "VERSION_PATH=%TARGET_DIR%\version.txt"
set "CHANNEL=stable"
set "RELEASE_API="
set "DOWNLOAD_URL="

echo.
echo ACS Tool Updater
echo.
if /I "%~1"=="testing" set "CHANNEL=testing"
if /I "%~1"=="stable" set "CHANNEL=stable"
if /I "%CHANNEL%"=="testing" (
    set "RELEASE_API=https://api.github.com/repos/%REPOSITORY%/releases"
) else (
    set "RELEASE_API=https://api.github.com/repos/%REPOSITORY%/releases/latest"
    set "DOWNLOAD_URL=https://github.com/%REPOSITORY%/releases/latest/download/%ASSET_NAME%"
)

if /I not "%~1"=="stable" if /I not "%~1"=="testing" if not "%~1"=="" (
    echo Unknown channel "%~1". Use "stable" or "testing".
    echo.
    pause
    exit /b 1
)

if "%~1"=="" (
    choice /C ST /N /M "Press S for stable release or T for testing build: "
    if errorlevel 2 set "CHANNEL=testing"
    if errorlevel 1 if not errorlevel 2 set "CHANNEL=stable"
    if /I "%CHANNEL%"=="testing" set "RELEASE_API=https://api.github.com/repos/%REPOSITORY%/releases"
)

echo Select the existing ACS Tool install folder when prompted.
echo.

for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Add-Type -AssemblyName System.Windows.Forms; $dialog = New-Object System.Windows.Forms.FolderBrowserDialog; $dialog.Description = 'Select the existing ACS Tool install folder'; $dialog.ShowNewFolderButton = $false; if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { [Console]::Write($dialog.SelectedPath) }"`) do set "TARGET_DIR=%%I"

if not defined TARGET_DIR (
    echo No folder was selected.
    echo.
    pause
    exit /b 1
)

set "APP_EXE=%TARGET_DIR%\ACS_Wynn_Builder.exe"
if not exist "%APP_EXE%" (
    echo The selected folder does not contain ACS_Wynn_Builder.exe
    echo.
    echo %TARGET_DIR%
    echo.
    pause
    exit /b 1
)

set "LOCAL_VERSION="
if exist "%TARGET_DIR%\version.txt" (
    set /p LOCAL_VERSION=<"%TARGET_DIR%\version.txt"
)

for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ProgressPreference='SilentlyContinue';" ^
  "$release = Invoke-RestMethod -UseBasicParsing -Uri '%RELEASE_API%';" ^
  "if ('%CHANNEL%' -eq 'testing') { $release = $release | Where-Object { -not $_.draft -and $_.prerelease } | Select-Object -First 1 };" ^
  "if (-not $release) { exit 3 };" ^
  "$tag = [string]$release.tag_name;" ^
  "if ($tag.StartsWith('v')) { $tag = $tag.Substring(1) };" ^
  "$asset = $release.assets | Where-Object { $_.name -eq '%ASSET_NAME%' } | Select-Object -First 1;" ^
  "if (-not $asset) { $asset = $release.assets | Where-Object { $_.name -match '\.(zip|exe)$' } | Select-Object -First 1 };" ^
  "if (-not $asset) { exit 4 };" ^
  "[Console]::WriteLine($tag);" ^
  "[Console]::Write([string]$asset.browser_download_url)"`) do (
    if not defined LATEST_VERSION (
        set "LATEST_VERSION=%%I"
    ) else (
        set "DOWNLOAD_URL=%%I"
    )
)

if not defined LATEST_VERSION (
    echo Could not determine the latest GitHub %CHANNEL% version.
    echo.
    pause
    exit /b 1
)

if not defined DOWNLOAD_URL (
    echo Could not determine the GitHub download URL for the %CHANNEL% channel.
    echo.
    pause
    exit /b 1
)

if defined LOCAL_VERSION if /I "%LOCAL_VERSION%"=="%LATEST_VERSION%" (
    echo ACS Tool is already up to date with %CHANNEL% version %LOCAL_VERSION%.
    echo.
    pause
    exit /b 0
)

echo Closing ACS Tool if it is running...
taskkill /IM ACS_Wynn_Builder.exe /F >nul 2>nul
timeout /t 2 /nobreak >nul

if exist "%TEMP_ROOT%" rmdir /s /q "%TEMP_ROOT%" >nul 2>nul
mkdir "%TEMP_ROOT%" >nul 2>nul

echo Downloading latest %CHANNEL% build from GitHub...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -TimeoutSec 30 -Uri '%DOWNLOAD_URL%' -OutFile '%ZIP_PATH%'"
if errorlevel 1 goto :download_failed

echo Extracting update package...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; Expand-Archive -LiteralPath '%ZIP_PATH%' -DestinationPath '%EXTRACT_PATH%' -Force"
if errorlevel 1 goto :extract_failed

echo Replacing files in %TARGET_DIR% ...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "$extract='%EXTRACT_PATH%';" ^
  "$target='%TARGET_DIR%';" ^
  "$items=Get-ChildItem -LiteralPath $extract;" ^
  "$source=if($items.Count -eq 1 -and $items[0].PSIsContainer){$items[0].FullName}else{$extract};" ^
  "Get-ChildItem -LiteralPath $source -Force | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $target -Recurse -Force }"
if errorlevel 1 goto :copy_failed

echo Relaunching ACS Tool...
start "" "%APP_EXE%"

echo.
echo Update completed successfully.
echo.
goto :cleanup

:download_failed
echo.
echo Download failed. Please check your internet connection or GitHub release availability.
echo.
goto :cleanup_pause

:extract_failed
echo.
echo Extraction failed. The downloaded package may be invalid.
echo.
goto :cleanup_pause

:copy_failed
echo.
echo File replacement failed. Make sure ACS Tool is fully closed, then try again.
echo.
goto :cleanup_pause

:cleanup_pause
pause

:cleanup
if exist "%TEMP_ROOT%" rmdir /s /q "%TEMP_ROOT%" >nul 2>nul
endlocal
exit /b 0
