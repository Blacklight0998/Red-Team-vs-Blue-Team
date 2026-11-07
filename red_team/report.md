# Red Team Attack Report

> Fill in each section after running the tools in this folder. Keep the
> structure: objective, methodology, evidence, reflection, recommendations.
> This mirrors the triage-report discipline used in the Enterprise SOC Lab
> (observed facts separated from interpretation).

## 1. Engagement Information

| Field | Value |
|---|---|
| **Target** | Blue Team VM, `[hostname/IP]` |
| **Operating System** | `[Ubuntu/Debian version]` |
| **Date(s)** | `[dates tested]` |
| **Tester** | Andy Vega |
| **Authorization** | Course-assigned Red Team vs Blue Team exercise |

## 2. Objective

What this engagement set out to find: exposed services, weak credentials,
and whether an on-path attacker could manipulate traffic between the
target and its gateway.

## 3. Methodology

1. **Reconnaissance (`scanner.py`):** Nmap service scan plus a custom
   Scapy SYN scan, to compare an automated tool against a hand-built one.
2. **Credential testing (`ssh_brute.py`):** dictionary attack against SSH
   with a small, explicit wordlist.
3. **Network manipulation (`packet_attack.py`):** ARP spoofing attempt
   against the target and its gateway, preceded by the pre-flight check
   described in `README.md`.

## 4. Findings

### 4.1 Port / Service Scan

`[Paste the relevant part of the scanner.py JSON report, or a summary
table: port, state, service, version.]`

### 4.2 SSH Dictionary Attack

`[Result: credential found / not found. If found, state the weak password
and recommend a fix - never store or publish the live password once the
exercise is graded; replace it with "[REDACTED - reported to Blue Team]".]`

### 4.3 ARP Spoofing

`[State the pre-flight check result first: did Azure block it or not?
Then describe what packet_attack.py did or didn't achieve, with evidence
(ARP table before/after, Wireshark capture if available).]`

## 5. Evidence

`[Screenshots and/or JSON report excerpts go here, one per finding above.
Reference files as ./evidence/0X_description.png, consistent with the
numbering convention used in the Enterprise SOC Lab's triage reports.]`

## 6. Reflection: How Effective Was the Blue Team's Defense?

`[Did they detect the scan/brute force/spoofing attempt? Did a firewall
rule block anything before it reached the service? Be specific and fair -
this is an evaluation of their controls, not a score.]`

## 7. Recommendations

`[For each finding in Section 4, a concrete fix: e.g. "disable password
auth on SSH, use key-based auth"; "restrict exposed ports via NSG/ufw to
only what's required"; "if ARP spoofing succeeded, recommend Dynamic ARP
Inspection or static ARP entries for the gateway".]`
