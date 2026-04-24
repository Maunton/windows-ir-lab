# Windows IR Lab

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-lightgrey)
![Sysmon](https://img.shields.io/badge/Telemetry-Sysmon-red)
![PowerShell](https://img.shields.io/badge/PowerShell-Logging-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![DFIR](https://img.shields.io/badge/Focus-DFIR%20%2F%20SOC-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Overview

**Windows IR Lab** is a Windows-focused incident response and detection engineering project built for home-lab testing, SOC practice, and DFIR portfolio development.

The project collects Windows Security, PowerShell, Sysmon, browser, and host context data, then turns that telemetry into structured analyst reports, stakeholder summaries, ATT&CK-tagged detection views, and portable HTML output.

This project is designed to show practical incident response skills without requiring a full enterprise SIEM.

## Why This Project Matters

Modern SOC and DFIR work is not just about collecting logs. Analysts need to understand what telemetry matters, reduce false positives, map suspicious activity to ATT&CK techniques, and communicate findings clearly.

This project demonstrates the ability to:

- Collect and normalize Windows endpoint telemetry.
- Analyze PowerShell, Security, and Sysmon events.
- Tune noisy detections and reduce false positives.
- Map suspicious behavior to MITRE ATT&CK.
- Generate reports for both technical analysts and non-technical stakeholders.
- Build a repeatable home-lab workflow for detection validation.

## Project Objectives

- Build a Windows-native incident response reporting tool.
- Collect security-relevant endpoint telemetry.
- Generate analyst-friendly and stakeholder-friendly reports.
- Support safe home-lab validation commands.
- Demonstrate detection logic, triage workflow, and ATT&CK mapping.
- Present the project clearly for cybersecurity employers and recruiters.

## Tools and Technologies

| Tool / Component | Purpose |
|---|---|
| Python | Core reporting tool |
| PowerShell | Windows event collection and validation |
| Windows Event Logs | Security and PowerShell telemetry |
| Sysmon | Extended endpoint telemetry |
| MITRE ATT&CK | Detection mapping and analyst context |
| HTML / Markdown | Portable report output |
| GitHub Pages | Hosted sample output |
| GitHub Actions | Python syntax validation |
| MIT License | Open-source project licensing |

## Repository Structure

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
│   ├── TESTING_MATRIX.md
│   ├── index.html
│   ├── sample_analyst_report.html
│   └── sample_stakeholder_summary.html
├── scripts/
│   └── windows_ir_reporter.py
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

## Detection and Reporting Workflow

```text
Windows Endpoint
      ↓
Security Logs / PowerShell Logs / Sysmon Logs / Host Context
      ↓
Python IR Reporter
      ↓
Detection Logic + Noise Reduction + ATT&CK Mapping
      ↓
Analyst Report + Stakeholder Summary + JSON Evidence
      ↓
Review, Triage, and Documentation
```

## Current Capabilities

- Windows Security log collection and triage.
- PowerShell telemetry review.
- Sysmon event analysis.
- Host context collection.
- Persistence inventory checks.
- Browser and endpoint noise tuning.
- Named detections with severity.
- ATT&CK-tagged analyst findings.
- Analyst report generation.
- Stakeholder summary generation.
- HTML and Markdown report output.
- Raw JSON output for follow-on analysis.
- Safe validation commands for controlled home-lab testing.

## Sample Outputs

- [Live Sample Outputs Page](https://maunton.github.io/windows-ir-lab/)
- [Sample Analyst Report](https://maunton.github.io/windows-ir-lab/sample_analyst_report.html)
- [Sample Stakeholder Summary](https://maunton.github.io/windows-ir-lab/sample_stakeholder_summary.html)

## Detection Example

Below is an example of the type of analysis this tool produces during a lab run:

- PowerShell execution detected with command-line arguments.
- Web request activity observed via PowerShell.
- Persistence indicators identified through Run key analysis.
- Scheduled task creation detected.

Each detection is:
- Assigned a severity level
- Tagged with a MITRE ATT&CK technique
- Included in both analyst and stakeholder reports

This demonstrates how raw telemetry is transformed into actionable findings that support incident response workflows.

## Example Analyst Finding

**Detection:** Suspicious PowerShell Execution  
**Severity:** Medium  
**ATT&CK Technique:** T1059.001 (PowerShell)

**Summary:**
PowerShell was executed with command-line arguments indicating potential script execution. This behavior may indicate administrative activity or early-stage execution techniques used by attackers.

**Recommended Action:**
- Review command-line arguments
- Validate user context
- Correlate with network activity

## Quick Start

### 1. Clone the Repository

```powershell
git clone https://github.com/Maunton/Windows-IR-Lab.git
cd Windows-IR-Lab
```

### 2. Review Logging Requirements

Recommended Windows logging setup:

- Enable Security process creation auditing.
- Enable command-line process auditing.
- Enable PowerShell script block logging.
- Install Sysmon with the provided balanced configuration.

Sysmon config path:

```text
config/sysmon-balanced.xml
```

### 3. Run the Reporter

```powershell
python .\scripts\windows_ir_reporter.py --days 2 --max-events 800 --outdir .\reports
```

### 4. Review Report Output

Open the generated report files:

```text
reports/windows_ir_analyst_report.html
reports/windows_ir_analyst_report.md
reports/windows_ir_stakeholder_summary.html
```

## Safe Home-Lab Validation Commands

These commands are intended for controlled testing on your own Windows lab machine.

```powershell
notepad.exe

Start-Process cmd.exe -ArgumentList '/c echo test-from-cmd > "$env:USERPROFILE\Desktop\ir_test_cmd.txt"'

Invoke-WebRequest -Uri "https://example.com" -OutFile "$env:USERPROFILE\Desktop\example_test.html"

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v IRTestRun /t REG_SZ /d "notepad.exe" /f

schtasks /create /sc once /tn IRTestTask /tr "notepad.exe" /st 23:59 /f
```

## Detection Coverage

Current detection logic includes coverage for:

| Area | Example Coverage |
|---|---|
| Execution | PowerShell and command shell activity |
| Ingress Tool Transfer | PowerShell web request activity |
| Persistence | Run key and scheduled task style checks |
| Endpoint Context | OS, AV status, service state, and host context |
| Sysmon Telemetry | Process, file, registry, DNS, and network activity |
| False Positive Tuning | Browser, Bitdefender, and known helper process noise reduction |
| ATT&CK Mapping | Technique tagging for analyst-facing detections |

## Best Operating Ranges

| Time Window | Recommended Use |
|---|---|
| 1–2 days | Best for clean incident storytelling |
| 3 days | Strong balance between context and noise |
| 7 days | Useful for broader hunting, but event caps may skew toward recent activity |

## What Employers Should Notice

This project demonstrates practical cybersecurity skills that map directly to SOC, DFIR, detection engineering, and security analyst work.

Key strengths shown:

- Built a working Windows incident response reporting tool.
- Used Python to automate endpoint telemetry collection and reporting.
- Incorporated Windows Security, PowerShell, and Sysmon log sources.
- Tuned detections to reduce false positives and analyst noise.
- Mapped detections to MITRE ATT&CK.
- Created both analyst-level and stakeholder-level reports.
- Built a repeatable home-lab validation process.
- Documented the project clearly for technical review.
- Demonstrated the ability to communicate findings to different audiences.
- Created a portfolio-ready project that shows real defensive security workflow.

## Portfolio Value

This repo is especially strong for cybersecurity job applications because it shows more than tool usage.

It shows that you can:

- Build security tooling.
- Understand Windows telemetry.
- Think like a SOC analyst.
- Reduce noise and improve signal.
- Document evidence.
- Create reporting that supports decision-making.
- Explain technical work in a professional format.

## Lessons Learned

- High-quality telemetry depends on proper Windows logging configuration.
- Sysmon adds valuable context but requires tuning to avoid noise.
- Analyst reports and stakeholder summaries serve different audiences.
- False-positive reduction is an important part of detection engineering.
- ATT&CK mapping helps detections become easier to explain and defend.
- Shorter review windows often produce cleaner incident narratives.

## Known Limitations

- Designed for Windows-native execution.
- Best results usually come from 1–3 day review windows.
- Longer time windows may skew results when event caps are reached.
- Sysmon is optional but strongly recommended.
- This is a home-lab project, not a replacement for enterprise SIEM, EDR, or case management tooling.

## Future Improvements

- Add more screenshots of generated reports.
- Add a demo GIF showing reporter execution and report review.
- Add sample JSON output examples.
- Add more detection examples mapped to ATT&CK.
- Add a detection coverage matrix.
- Add Sigma-rule style mappings.
- Add unit tests for parsing and detection functions.
- Expand documentation for Windows logging setup.
- Add release packages for easier download.
- Add report comparison examples across different test runs.

## Disclaimer

This project is for educational, portfolio, and controlled home-lab use only. Run validation commands only on systems you own or are authorized to test. This project is not a replacement for enterprise incident response tooling, SIEM platforms, EDR products, or professional forensic procedures.
