# ACS Wynn Builder Release Workflow

This project now supports two separate GitHub-backed update channels:

- `stable`: normal published releases for coworkers
- `testing`: prerelease builds for work-laptop validation

The app UI now uses a single `UPDATE APP` flow:

- it opens a chooser with the 10 most recent GitHub releases
- each entry is labeled `latest stable`, `stable`, or `testing`
- coworkers can install an older known-good build when needed

## Build And Package

Run these commands from PowerShell:

```powershell
# Stable release package
powershell -ExecutionPolicy Bypass -File C:\Users\congi\OneDrive\Desktop\ACS_Wynn_Builder\ACS_Wynn_Builder\package_acs_tool.ps1 -Channel stable

# Testing package with automatic prerelease version suffix
powershell -ExecutionPolicy Bypass -File C:\Users\congi\OneDrive\Desktop\ACS_Wynn_Builder\ACS_Wynn_Builder\package_acs_tool.ps1 -Channel testing

# Testing package with an explicit version label
powershell -ExecutionPolicy Bypass -File C:\Users\congi\OneDrive\Desktop\ACS_Wynn_Builder\ACS_Wynn_Builder\package_acs_tool.ps1 -Channel testing -VersionLabel 2.3.12-testing.1
```

## Packaging Output

The packaging script now creates:

- a runnable install folder on the Desktop
- a channel-specific artifact folder under `dist\artifacts\stable` or `dist\artifacts\testing`
- a fixed updater asset named `ACS_Wynn_Builder_Update.zip`
- a matching SHA-256 file named `ACS_Wynn_Builder_Update.sha256`
- versioned archive copies for history

## GitHub Publish Rules

### Stable Channel

Publish a normal GitHub release and upload:

- `ACS_Wynn_Builder_Update.zip`
- `ACS_Wynn_Builder_Update.sha256`

Use the stable artifact folder:

- `C:\Users\congi\OneDrive\Desktop\ACS_Wynn_Builder\ACS_Wynn_Builder\dist\artifacts\stable`

### Testing Channel

Publish a GitHub prerelease and upload:

- `ACS_Wynn_Builder_Update.zip`
- `ACS_Wynn_Builder_Update.sha256`

Use the testing artifact folder:

- `C:\Users\congi\OneDrive\Desktop\ACS_Wynn_Builder\ACS_Wynn_Builder\dist\artifacts\testing`

Important:

- Keep the asset name exactly `ACS_Wynn_Builder_Update.zip`
- The app expects the testing channel to come from GitHub prereleases
- A testing version should use a prerelease-style label such as `2.3.12-testing` or `2.3.12-testing.1`

## Work Laptop Validation

After publishing a testing prerelease, verify on the VPN-connected work laptop:

1. Launch the current installed app.
2. Click `UPDATE APP`.
3. Confirm the chooser shows only the 10 most recent releases.
4. Confirm the newest stable entry is labeled `latest stable`.
5. Confirm prerelease entries are labeled `testing`.
6. Install the intended update.
7. Reopen the app and confirm the new version from `version.txt`.
8. Test Aruba connect/deploy behavior.
9. Test Cisco connect, WLAN ID check, and deploy behavior.

After publishing a stable release, verify:

1. Click `UPDATE APP`.
2. Confirm the chooser includes the new stable release within the 10 listed options.
3. Confirm it is labeled `latest stable`.
4. Install the update.
5. Confirm coworkers can still choose an older stable build if they need to roll back.

## Recovery Paths

The recovery helpers now support both channels:

- `ACS_Recovery_Tool.exe`
- `Update_ACS_Tool.cmd`
- `Update_ACS_Tool_Browse.cmd`

Each now allows choosing `stable` or `testing` instead of forcing only the latest public release.

## Version Guidance

Recommended pattern:

- stable: `2.3.13`
- testing: `2.3.13-testing.1`
- next testing revision: `2.3.13-testing.2`

This keeps the testing channel installable even when the base stable version number is the same.
