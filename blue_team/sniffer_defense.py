#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, ARP
import subprocess
import logging
from collections import defaultdict
import time
# Logging configuration
logging.basicConfig(
    filename="intrusion_defense.log",
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
# Control structures used for behavior analysis
puertos_escaneados = defaultdict(set)      # Used for port scans (Nmap -sS)
conteo_syn_flood = defaultdict(list)       # Used to track SYN packet rates
tabla_arp_conocida = {}                    # Used for ARP spoofing detection
# Alerting and blocking thresholds
UMBRAL_PUERTOS_DISTINTOS = 12  # More than 12 distinct ports -> Nmap-style scan
UMBRAL_SYN_RATE = 30           # More than 30 SYN packets within the time window
VENTANA_TIEMPO = 5.0           # Seconds used for the SYN-rate window
## PROGRAM FUNCTIONS ##
# Automatic malicious-IP blocking system using iptables
def bloquear_ip(ip_atacante, motivo):
    """Bloquea automáticamente la IP maliciosa usando iptables de Linux."""
    try:
        # Check whether the rule already exists to avoid duplicates
        verificacion = subprocess.run(
            f"sudo iptables -C INPUT -s {ip_atacante} -j DROP", 
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if verificacion.returncode != 0:
            # Apply the block in iptables
            subprocess.run(f"sudo iptables -A INPUT -s {ip_atacante} -j DROP", shell=True, check=True)
            mensaje = f"[BLOQUEO AUTOMÁTICO] IP bloqueada por '{motivo}': {ip_atacante}"
            print(f"\033[91m\n[!] {mensaje}\033[0m")
            logging.critical(mensaje)
        else:
            print(f"[*] La IP {ip_atacante} ya se encontraba previamente bloqueada.")
    except Exception as e:
        print(f"[-] Error crítico al aplicar iptables para {ip_atacante}: {e}")
# TCP traffic analyzer for port-scan and SYN-flood detection
def analizar_trafico_tcp(paquete):
    """Analiza paquetes IP/TCP en busca de patrones ofensivos."""
    if paquete.haslayer(IP) and paquete.haslayer(TCP):
        ip_origen = paquete[IP].src
        puerto_destino = paquete[TCP].dport
        flags = paquete[TCP].flags
        tiempo_actual = time.time()

        # Detection 1: Port scan (Nmap-style SYN scan, -sS)
        if flags == 'S':  # Pure SYN packet
            puertos_escaneados[ip_origen].add(puerto_destino)
            total_puertos = len(puertos_escaneados[ip_origen])

            if total_puertos > UMBRAL_PUERTOS_DISTINTOS:
                alerta = f"Escaneo de puertos detectado (Nmap). IP origen: {ip_origen} afectó {total_puertos} puertos."
                logging.warning(alerta)
                bloquear_ip(ip_origen, "Escaneo de Puertos / Nmap")
                # Clear this IP record to avoid repeated blocking loops
                puertos_escaneados[ip_origen].clear()

            # Detection 2: SYN-flood protection (denial of service)
            # Remove entries outside the time window
            conteo_syn_flood[ip_origen] = [t for t in conteo_syn_flood[ip_origen] if tiempo_actual - t < VENTANA_TIEMPO]
            conteo_syn_flood[ip_origen].append(tiempo_actual)

            if len(conteo_syn_flood[ip_origen]) > UMBRAL_SYN_RATE:
                alerta = f"Ataque DoS (SYN Flood) detectado desde la IP: {ip_origen}"
                logging.error(alerta)
                bloquear_ip(ip_origen, "SYN Flood Attack")
                conteo_syn_flood[ip_origen].clear()
# ARP traffic analyzer for ARP-spoofing detection
def analizar_trafico_arp(paquete):
    """Detecta posibles ataques de ARP Spoofing en la red local."""
    if paquete.haslayer(ARP):
        # ARP opcode 2 represents an ARP reply
        if paquete[ARP].op == 2:
            ip_real = paquete[ARP].psrc
            mac_recibida = paquete[ARP].hwsrc

            # If the recorded MAC for this IP changes unexpectedly, treat it as possible spoofing
            if ip_real in tabla_arp_conocida:
                if tabla_arp_conocida[ip_real] != mac_recibida:
                    alerta = f"¡ALERTA DE ARP SPOOFING! La IP {ip_real} cambió su MAC de {tabla_arp_conocida[ip_real]} a {mac_recibida}"
                    print(f"\033[93m\n[!] {alerta}\033[0m")
                    logging.critical(alerta)
            else:
                tabla_arp_conocida[ip_real] = mac_recibida
# Main function that routes packet processing
def procesar_paquete(paquete):
    """Función enrutadora que procesa cada paquete capturado por Scapy."""
    analizar_trafico_tcp(paquete)
    analizar_trafico_arp(paquete)
# IDS and active-defense startup function
def iniciar_ids():
    print("=" * 60)
    print("  BLUE TEAM: IDS & Active Defense (Scapy + Iptables)")
    print("=" * 60)
    print("[*] Monitoreando interfaces de red en busca de anomalías...")
    print("[*] Reglas activas: Detección de Nmap, SYN Flood y ARP Spoofing.")
    print("[*] Presiona Ctrl+C para detener el sistema de defensa.\n")
    
    try:
        # Continuously capture network packets
        sniff(prn=procesar_paquete, store=False)
    except PermissionError:
        print("\n[-] Error: Se requieren permisos de superusuario (sudo) para capturar tráfico y modificar iptables.")
    except KeyboardInterrupt:
        print("\n\n[*] Sistema IDS detenido de forma segura. Logs guardados en 'intrusion_defense.log'.")
# Program entry point
if __name__ == "__main__":
    iniciar_ids()