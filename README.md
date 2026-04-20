````md
# Windows IR Lab

A Windows-focused incident response and detection lab for home enthusiasts, students, and aspiring SOC / DFIR analysts.

This project collects Windows Security, PowerShell, Sysmon, and endpoint context, then turns that data into:

- a full **analyst report**
- a concise **stakeholder summary**
- an **ATT&CK-tagged detection view**
- a clean, portable **HTML report package**

It is designed for people who want to practice Windows telemetry analysis on a personal lab machine without needing a full enterprise SIEM.

## Why this project matters

This repo demonstrates practical experience in:

- Windows event log collection and triage
- PowerShell and Sysmon telemetry analysis
- detection engineering and false-positive tuning
- ATT&CK mapping for analyst-facing detections
- report generation for technical and non-technical audiences
- home-lab focused security engineering

## What it does

The reporter collects and correlates:

- **Windows Security logs** (process creation and related events)
- **PowerShell logs** (including script block logging)
- **Sysmon logs** (process, file, registry, DNS, network, and extended telemetry)
- **host context** like OS version, AV status, persistence inventory, and service state

Then it generates:

- `windows_ir_analyst_report.html`
- `windows_ir_analyst_report.md`
- `windows_ir_stakeholder_summary.html`
- raw JSON output for follow-on triage

## Current features

- Full analyst and stakeholder report split
- HTML reports with navigation, filters, and print/export styling
- Named detections with severity and triage actions
- ATT&CK technique tagging for analyst detections
- Browser / Bitdefender false-positive tuning
- PowerShell / Sysmon noise suppression
- Persistence inventory checks
- Case workflow summary and evidence guidance

## Project status

This project is in the **validation and tuning** phase.

It is stable enough for:

- home-lab testing
- detection demonstrations
- GitHub portfolio presentation
- explaining detection logic to employers

It is not positioned as a replacement for enterprise IR tooling.

## Repo layout

```text
windows-ir-lab/
├── .github/
│   └── workflows/
│       └── python-syntax-check.yml
├── config/
│   └── sysmon-balanced.xml
├── docs/
│   ├── GITHUB_PREVIEW.md
│   ├── HOME_LAB_SETUP.md
│   ├── PROJECT_ROADMAP.md
│   └── TESTING_MATRIX.md
├── examples/
│   └── README.md
├── scripts/
│   └── windows_ir_reporter.py
├── .gitignore
├── requirements.txt
└── README.md
````

## Quick start

### 1. Enable Windows logging

Recommended:

* Security process creation auditing
* PowerShell script block logging
* Sysmon with the sample config in `config/sysmon-balanced.xml`

### 2. Run the reporter

From PowerShell:

```powershell
python .\scripts\windows_ir_reporter.py --days 2 --max-events 800 --outdir .\reports
```

### 3. Review outputs

Open:

* `windows_ir_analyst_report.html`
* `windows_ir_stakeholder_summary.html`

## Suggested test commands

These are safe home-lab validation actions that help exercise the reporter:

```powershell
notepad.exe
Start-Process cmd.exe -ArgumentList '/c echo test-from-cmd > "$env:USERPROFILE\Desktop\ir_test_cmd.txt"'
Invoke-WebRequest -Uri "https://example.com" -OutFile "$env:USERPROFILE\Desktop\example_test.html"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v IRTestRun /t REG_SZ /d "notepad.exe" /f
schtasks /create /sc once /tn IRTestTask /tr "notepad.exe" /st 23:59 /f
```

## Best operating ranges

Based on tuning so far:

* **1–2 days** = best for clean incident storytelling
* **3 days** = strong balance between context and noise
* **7 days** = usable for broader hunting, but capped logs can skew the report toward recent activity

## Who this is for

* home-lab security enthusiasts
* SOC / DFIR learners
* junior detection engineers
* candidates building a practical cybersecurity GitHub portfolio

## Portfolio value

This repo is strong for employers because it shows:

* you can build and iterate on a working security tool
* you understand telemetry, false positives, and analyst workflow
* you can present technical output clearly to different audiences
* you can connect detections to ATT&CK rather than only raw logs

## Notes

* This project is Windows-specific.
* Python dependencies are currently standard-library only.
* The script should be run in a controlled home-lab or personal test environment.

```
```
