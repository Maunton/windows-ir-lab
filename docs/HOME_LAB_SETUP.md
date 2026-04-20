# Home Lab Setup

## Recommended environment

- Windows 11 test machine
- Python 3.11+
- PowerShell
- Sysmon installed with `config/sysmon-balanced.xml`
- PowerShell Script Block Logging enabled

## Basic run command

```powershell
python .\scripts\windows_ir_reporter.py --days 2 --max-events 800 --outdir .\reports
```
