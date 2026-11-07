# Red Team Toolkit

Offensive tooling built for the course project "Red Team vs Blue Team en la
Nube: Ataque y Defensa en Azure", targeting a Blue Team VM we are explicitly
authorized to test.

> **Scope.** Every script here refuses to run unless the target matches
> `authorized_target.txt` (one line, the Blue Team VM's IP/hostname) and the
> operator types an explicit confirmation. See `modules/authorization.py`.

## Tools

| Script | Purpose | Reused from portfolio |
|---|---|---|
| `scanner.py` | Port/service scan: real Nmap (`python-nmap`) plus a hand-written raw TCP SYN scanner | SYN-scan logic adapted from [`python-security-tools/network-recon-tool`](../python-security-tools/network-recon-tool/) |
| `ssh_brute.py` | Controlled SSH dictionary attack (Paramiko) | New |
| `packet_attack.py` | ARP spoofing against the Blue Team VM | New |
| `modules/reporting.py` | Shared JSON report writer | Pattern reused from the recon tool's `reporting.py` |
| `modules/authorization.py` | Shared scope/consent check | New |
| `report.md` | Write-up of what was found | Template |

Every run writes a timestamped JSON report to `reports/`.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`scanner.py` calls the real `nmap` binary through `python-nmap`, so Nmap
itself must also be installed on the system (`sudo apt install nmap`).

Create `authorized_target.txt` in this folder with one line: the Blue Team
VM's IP or hostname.

### About the wordlist

`ssh_brute.py` ships with a small built-in list, but you can point it at
any wordlist file. Prefer a small, curated list over a huge one — a real
attacker tries the most common passwords first, not every possible one,
and a large list is very likely to just trigger Fail2ban (or another
rate-limiting defense the Blue Team may have configured) after a handful
of attempts, wasting hours for no extra result. A few hundred entries from
a reputable source is enough:

```bash
curl -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/500-worst-passwords.txt
```

If you do get blocked, that's not a failure of the tool — `ssh_brute.py`
detects repeated connection refusals and reports `likely_blocked_by_rate_limiting:
true`. Getting banned after N attempts is itself a legitimate finding:
it shows the Blue Team's rate-limiting works, and N tells you how
sensitive their threshold is.

## Pre-flight check: does ARP spoofing even work here?

**Do this before relying on `packet_attack.py` for the report.** Azure's
virtual network layer commonly blocks ARP spoofing between VMs by design.
Confirm with a quick manual test first:

1. From the Red Team VM: `sudo apt install dsniff` then
   `sudo arpspoof -i eth0 -t <blue_team_ip> <gateway_ip>` for about a minute.
2. On the Blue Team VM (or a third host on the same subnet), check the ARP
   table before and during the test: `ip neigh show` (Linux) or
   `arp -a` (Windows).
3. If the Blue Team VM's ARP entry for the gateway changes to the Red Team
   VM's MAC address, the attack works here — proceed with `packet_attack.py`
   and document normally.
4. If it never changes, that is still a valid, documented finding: Azure's
   SDN is filtering the spoofed ARP replies. Screenshot the unchanged ARP
   table and note it in `report.md` as a platform-level mitigation, rather
   than a flaw in the script.

## Usage

```bash
python scanner.py       # Nmap + custom Scapy SYN scan
python ssh_brute.py      # Paramiko dictionary attack
sudo python packet_attack.py   # ARP spoofing (needs raw-socket privileges)
```

## How to evaluate success

Each tool's JSON report in `reports/` is the source of truth; use it like this:

| Tool | Success looks like | Failure looks like |
|---|---|---|
| `scanner.py` | Open ports with correctly identified services/versions; at least one entry in `risky_ports` if the target exposes something like FTP/Telnet/RDP unnecessarily | All ports `filtered` (NSG is restrictive) or the `basic`/`aggressive` profiles return nothing without `sudo` |
| `ssh_brute.py` | `credential_found: true`, with the weak password that worked | `credential_found: false` (strong password) **or** `likely_blocked_by_rate_limiting: true` (Blue Team's Fail2ban/rate-limit worked — also a valid, documented outcome) |
| `packet_attack.py` | The target's ARP table for the gateway changes to the Red Team VM's MAC during the attack window, confirmed via `ip neigh show`/Wireshark | MAC resolution fails, or the ARP table never changes — likely Azure's SDN filtering it (see "Pre-flight check" above); document this as a platform-level mitigation, not a bug |

In short: a "failure" in any of these tools is not a wasted run. A blocked
scan, a blocked brute force, or a blocked spoof attempt is exactly the kind
of evidence `report.md` Section 6 ("How effective was the Blue Team's
defense?") is asking for.

## Ethics

These tools are built for, and must only be run against, the Blue Team VM
assigned for this course exercise. They are not to be pointed at any other
host, network, or account.
