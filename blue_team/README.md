# Blue Team — Monitoring, Detection & Automated Defense

**Contributor:** Gabriel Villalobos Alpízar  
**Original project:** [GaboX280/NexusSIEM](https://github.com/GaboX280/NexusSIEM)

This directory contains the Blue Team contribution to the university Red Team vs Blue Team project.

## Components

- `web_app/` — Flask-based monitoring dashboard and alert API;
- `sniffer_defense.py` — Scapy-based network monitoring and active response;
- `ssh_defender.py` — SSH failed-login monitoring and automated blocking;
- `firewall_hardening.sh` — UFW hardening and SSH rate limiting;
- `atom_launcher.py` — launcher for the system-auditing component used in the project.

## Defensive focus

The module is designed to monitor controlled attack activity, identify suspicious network or authentication behavior and apply basic defensive actions inside the authorized lab environment.

## Code preservation

The executable code in this directory is preserved from the original NexusSIEM Blue Team implementation. For the combined English-language repository, only comments were translated where necessary. Logic, variables, function names, parameters and runtime behavior were not rewritten for presentation.
