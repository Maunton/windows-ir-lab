# Windows IR Lab desktop app

## Download and run

The desktop package targets Windows 10/11 x64. Python and Git are not needed on the recipient's PC. Windows PowerShell must be available. Sysmon is optional; the app does not install it or enable auditing.

1. Download `Windows-IR-Lab-Windows-x64.zip` from a published GitHub Release (once available).
2. Right-click the ZIP and choose **Extract All**. Keep each EXE with its `_internal` folder.
3. Open `Windows-IR-Lab/Windows-IR-Lab.exe`.
4. Choose the time window, event limit and output folder. Browser history is off by default.
5. Click **Generate reports**, then **Open report folder**. Open `windows_ir_analyst_report.html` or `windows_ir_stakeholder_summary.html`.

Each desktop run gets its own folder. `collection.log` records execution errors. Collection runs in the background so the window stays responsive. Individual PowerShell commands time out after three minutes; a full run can take longer.

For protected Security logs, close the app and right-click the EXE → **Run as administrator**. Use a trusted extraction folder that other users cannot modify. Running under a different administrator account changes the user context and browser profile collected.

Reports contain potentially sensitive local evidence. The application does not upload reports. Browser collection is optional; event logs can still contain URLs and command lines. Findings require analyst review. Missing logs, event caps, and collection errors limit coverage; no detections does not mean the computer is clean. This app does not remove malware.

The initial build is unsigned, so Windows may display an unknown-publisher or SmartScreen warning. Verify its source and checksum; do not disable security protection. Public distribution can later use a code-signing certificate.

## Command-line version

`Windows-IR-CLI/Windows-IR-CLI.exe --days 3 --max-events 400 --skip-browser-history --outdir C:\IR-Reports\case-001`

The CLI retains the existing browser-history default for compatibility. Use `--skip-browser-history` to exclude it. Unlike the desktop app, repeated CLI runs into the same directory overwrite the report files.

## Build and share

The **Build Windows desktop app** GitHub Actions workflow tests and builds on Windows. Download its `Windows-IR-Lab-Windows-x64` artifact, then extract the contained ZIP and `SHA256SUMS.txt`. Actions downloads require GitHub sign-in; a public GitHub Release asset gives recipients a normal download link without a GitHub account.

Before publishing a release, test the desktop app on a clean Windows x64 VM without Python, both normally and elevated. Generate reports with missing Sysmon, confirm error/coverage messages, and verify browser-history opt-out. CI checks startup and synthetic report generation; it does not certify real-machine collection. Attach the ZIP and checksum to a release only after these checks pass. No release is automatically published by this workflow.

To check the download:

```powershell
Get-FileHash .\Windows-IR-Lab-Windows-x64.zip -Algorithm SHA256
```

Compare with the SHA256SUMS file from the same build.

To build locally on Windows with Python 3.12:

```powershell
python -m pip install -r requirements-build.txt
python -m unittest discover -s tests -v
python -m PyInstaller --noconfirm --clean --onedir --windowed --name Windows-IR-Lab scripts/windows_ir_app.py
```

Share the entire `dist\Windows-IR-Lab` folder as a ZIP. PyInstaller's folder bundle includes Python and Tk; the EXE is not a standalone file. The folder format avoids the temporary extraction used by one-file executables, especially relevant for elevated collection.

## Missing DNS or IP addresses

This reporter reads Sysmon event 22 (DNS queries/results) and event 3 (network connections). It does not use tcpdump, Wireshark, Npcap, or packet capture. A packet-capture driver is not required.

The earlier bundled XML had empty `include` filters, disabling DNS/network logging. The corrected baseline enables process creation, network connections and DNS queries with empty `exclude` filters. Other explicitly listed event types remain disabled pending tuning. This is a minimal baseline, not full coverage of every detection supported by the reporter.

For an existing standalone Sysinternals Sysmon installation, first inspect/save your current configuration and then apply the updated file from an elevated PowerShell in the repository (use your actual Sysmon64.exe path):

```powershell
.\Sysmon64.exe -c
.\Sysmon64.exe -c .\config\sysmon-balanced.xml
```

This replaces the active configuration. Do not replace an organization-managed or customized configuration without preserving its rules; merge the desired event filters instead. The desktop app does not apply this change automatically. A configuration change affects future events only, so it cannot recover missing historical DNS/IP evidence.

Generate a small test request and inspect the log:

```powershell
Invoke-WebRequest https://example.com -UseBasicParsing | Out-Null
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 3,22
    StartTime = (Get-Date).AddMinutes(-5)
} -MaxEvents 20 | Select-Object TimeCreated, Id, Message
```

Then run the reporter for one day. If events exist in Event Viewer but not in the report, try a higher event limit: in older builds all Sysmon event types share that limit. Version 0.2.1-preview queries network, DNS and other events separately. If the command reports access denied, use elevation. If the log is absent, check Sysmon installation/service status. DNS query results do not always contain an IP (for example, failed queries); network connection events are a separate evidence source.

See Microsoft's [Sysmon filtering documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) for event and filter semantics.


## 0.2.1 preview: independent network collection

Sysmon DNS (22), network connections (3), and other event types now have separate query budgets. With a limit of 5,000, up to 15,000 Sysmon events can be collected. Gaps / Notes lists the count, oldest/newest collected timestamps and cap status for each group. This prevents process-access and registry noise from consuming the DNS/network budget; any group can still reach its own cap. A three-day request does not guarantee three days of retained or collected evidence.

The app title identifies this build as 0.2.1-preview. Non-administrator launches now ask whether to continue with limited access. Failed log queries show an incomplete-collection banner in HTML reports. Neither change automatically elevates the app or changes Sysmon settings.
