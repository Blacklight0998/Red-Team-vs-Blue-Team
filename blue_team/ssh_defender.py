#!/usr/bin/env python3
import subprocess
import re
import time
import logging
from collections import defaultdict
# Logging configuration
logging.basicConfig(
    filename="ssh_defender.log",
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
# Monitoring configuration
LIMITE_FALLOS = 5 # Number of failed attempts before blocking
VENTANA_TIEMPO = 60  # Seconds
# Dictionary used to store failed-attempt timestamps per IP
intentos_fallidos = defaultdict(list)
## PROGRAM FUNCTIONS ##
# Function used to block malicious IP addresses with iptables
def bloquear_ip(ip_atacante):
    """Ejecuta iptables para bloquear la IP y registra la acción."""
    try:
        # Check whether the IP is already blocked
        verificacion = subprocess.run(
            f"sudo iptables -C INPUT -s {ip_atacante} -j DROP", 
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if verificacion.returncode != 0:
            subprocess.run(f"sudo iptables -A INPUT -s {ip_atacante} -j DROP", shell=True, check=True)
            mensaje = f"[BLOQUEO AUTOMÁTICO] IP bloqueada por fuerza bruta SSH: {ip_atacante}"
            print(f"\033[91m\n[!] {mensaje}\033[0m")
            logging.critical(mensaje)
        else:
            print(f"[*] La IP {ip_atacante} ya está bloqueada.")
    except Exception as e:
        print(f"[-] Error al bloquear la IP {ip_atacante}: {e}")
# Function used to analyze each log line and detect failed SSH attempts
def analizar_linea(linea):
    """Busca patrones de fallo de autenticación SSH y extrae la IP."""
    # Regular expression used to capture IPs in "Failed password" or "Invalid user" entries
    patron_ip = re.search(r"(Failed password|Invalid user).*from (\d+\.\d+\.\d+\.\d+)", linea)
    
    if patron_ip:
        ip_atacante = patron_ip.group(2)
        tiempo_actual = time.time()
        
        # Remove old entries outside the time window (60 seconds)
        intentos_fallidos[ip_atacante] = [t for t in intentos_fallidos[ip_atacante] if tiempo_actual - t < VENTANA_TIEMPO]
        
        # Record the new failed attempt
        intentos_fallidos[ip_atacante].append(tiempo_actual)
        fallos_recientes = len(intentos_fallidos[ip_atacante])
        
        print(f"[*] Intento fallido SSH detectado desde {ip_atacante} (Total reciente: {fallos_recientes})")
        
        # Check whether the configured threshold has been exceeded
        if fallos_recientes >= LIMITE_FALLOS:
            alerta = f"Ataque de fuerza bruta detectado desde {ip_atacante}."
            logging.error(alerta)
            bloquear_ip(ip_atacante)
            # Clear the history for this IP to avoid repeating the block on every following line
            intentos_fallidos[ip_atacante].clear()
# Main function used to start SSH log monitoring
def iniciar_monitoreo():
    print("=" * 60)
    print("  BLUE TEAM: SSH Defender (Prevención de Fuerza Bruta)")
    print("=" * 60)
    print(f"[*] Escuchando logs de autenticación mediante journalctl...")
    print(f"[*] Regla activa: Bloqueo tras {LIMITE_FALLOS} fallos en {VENTANA_TIEMPO}s.")
    print("[*] Presiona Ctrl+C para detener.\n")
    
    # Use journalctl to read SSH service logs in real time (-f)
    comando = ["journalctl", "-u", "ssh", "-f", "-n", "0"]
    
    try:
        proceso = subprocess.Popen(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for linea in proceso.stdout:
            analizar_linea(linea.strip())
    except PermissionError:
        print("\n[-] Error: Ejecuta el script con 'sudo' para leer logs y aplicar iptables.")
    except KeyboardInterrupt:
        print("\n[*] Monitoreo SSH detenido. Revisa 'ssh_defender.log' para detalles.")
# Program entry point
if __name__ == "__main__":
    iniciar_monitoreo()