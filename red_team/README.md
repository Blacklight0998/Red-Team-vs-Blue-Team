# Red Team Module

This directory contains the Red Team contribution represented by **Andy Vega Araya** within the Red Team vs Blue Team university group project.

The executable Python logic is preserved from the supplied Red Team module. This portfolio copy only reorganizes documentation and comments.

## Components

- `scanner.py` — Nmap + Scapy reconnaissance;
- `ssh_brute.py` — controlled SSH dictionary testing;
- `packet_attack.py` — ARP spoofing experiment;
- `modules/authorization.py` — authorized-target verification;
- `modules/reporting.py` — JSON result reporting;
- `reports/` — generated evidence;
- `report.md` — Red Team report template.

## Scope control

The offensive scripts are intended only for the authorized university lab target. `authorized_target.txt` is deliberately excluded from version control because it can contain a real lab IP or hostname.

For the original longer Red Team README supplied before integration, see [`../docs/original/RED_TEAM_README.md`](../docs/original/RED_TEAM_README.md).
