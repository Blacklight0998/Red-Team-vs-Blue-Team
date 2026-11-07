# Red Team contribution represented in this group repository: Andy Vega Araya.
# Executable logic preserved from the supplied Red Team module.
import nmap
from scapy.all import IP, TCP, send, sr1

from modules.authorization import confirm_authorized_target
from modules.reporting import save_report

DEFAULT_PORTS = "21-23,53,80,135,139,443,445,3389,8080"

SCAN_PROFILES = {
    "basic": "-sS",
    "version": "-sV",
    "aggressive": "-A",
    "slow_stealth": "-sS -T1",
    "no_ping": "-sV -Pn",
}

RISKY_PORTS = {
    21: "FTP - often unencrypted credentials",
    23: "Telnet - unencrypted, should not be exposed",
    135: "MSRPC - should not face the internet",
    139: "NetBIOS - legacy, should not face the internet",
    445: "SMB - frequent target if exposed externally",
    3389: "RDP - frequent brute-force target",
    5900: "VNC - often weak or no authentication",
}


def flag_risky_ports(findings):
    flags = []
    for item in findings:
        if item["state"] == "open" and item["port"] in RISKY_PORTS:
            flags.append({
                "port": item["port"],
                "service": item["service"],
                "reason": RISKY_PORTS[item["port"]],
            })
    return flags


def nmap_scan(target, profile, ports=DEFAULT_PORTS):
    arguments = SCAN_PROFILES[profile]
    scanner = nmap.PortScanner()
    print(f"[nmap] {profile} ({arguments}) on {target}, ports {ports}")
    scanner.scan(hosts=target, ports=ports, arguments=arguments)

    findings = []
    if target in scanner.all_hosts():
        host_data = scanner[target]
        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                info = host_data[proto][port]
                findings.append({
                    "port": port,
                    "protocol": proto,
                    "state": info.get("state"),
                    "service": info.get("name"),
                    "product": info.get("product"),
                    "version": info.get("version"),
                })
                print(f"[nmap] {port}/{proto} {info.get('state')} -> {info.get('name')} {info.get('product', '')} {info.get('version', '')}".rstrip())

    risky = flag_risky_ports(findings)
    for r in risky:
        print(f"[nmap] risky port {r['port']} ({r['service']}): {r['reason']}")

    return {
        "profile": profile,
        "nmap_arguments": arguments,
        "findings": findings,
        "risky_ports": risky,
    }


def scapy_syn_scan(host, ports):
    findings = []

    for port in ports:
        packet = IP(dst=host) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)

        if response is None:
            state = "filtered/no response"
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            state = "open"
            send(IP(dst=host) / TCP(dport=port, flags="R"), verbose=0)
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            state = "closed"
        else:
            state = "unknown"

        print(f"[scapy] {host}:{port} -> {state}")
        findings.append({"host": host, "port": port, "state": state})

    return findings


def main():
    print("Red Team Scanner")
    print("Use only against the Blue Team VM you are authorized to test.\n")

    target = input("Target IP/hostname: ").strip()
    confirm_authorized_target(target)

    print(f"\nProfiles available: {', '.join(SCAN_PROFILES)}")
    chosen = input("Profiles to run, comma-separated [basic,aggressive]: ").strip() or "basic,aggressive"
    profiles = [p.strip() for p in chosen.split(",") if p.strip() in SCAN_PROFILES]

    nmap_results = {}
    for profile in profiles:
        nmap_results[profile] = nmap_scan(target, profile)

    compare_ports = [21, 22, 23, 80, 443, 3389]
    scapy_results = scapy_syn_scan(target, compare_ports)

    report_path = save_report(
        tool_name="scanner",
        target=target,
        data={"nmap": nmap_results, "scapy_syn": scapy_results},
    )
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
