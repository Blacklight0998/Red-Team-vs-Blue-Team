#!/bin/bash
echo "[*] Iniciando el proceso de Hardening del Firewall (UFW)..."
# 1. Ensure the script is executed as root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Por favor, ejecuta este script como root (sudo ./firewall_hardening.sh)"
  exit 1
fi
# 2. Reset UFW to its default state to avoid conflicts
echo "[+] Reseteando reglas anteriores de UFW..."
ufw --force reset
# 3. Default policies (deny incoming traffic, allow outgoing traffic)
echo "[+] Configurando políticas por defecto..."
ufw default deny incoming
ufw default allow outgoing
# 4. Allow essential traffic (ports 80 and 443 for web services, when applicable)
echo "[+] Abriendo puertos permitidos (HTTP/HTTPS)..."
ufw allow 80/tcp
ufw allow 443/tcp
# 5. Advanced configuration: SSH rate limiting (port 22)
# This denies connections when one IP repeatedly attempts to log in within a short interval,
# complementing the Python ssh_defender.py control used in the university exercise.
echo "[+] Configurando Rate-limiting (limitación de tasa) para SSH en el puerto 22..."
ufw limit 22/tcp
# 6. Enable logging for blocked packets
echo "[+] Activando logging para registrar paquetes sospechosos bloqueados..."
ufw logging on
# 7. Enable the firewall
echo "[+] Habilitando UFW..."
ufw --force enable
echo "[===================================================]"
echo "[✔] Hardening completado. Estado actual del firewall:"
echo "[===================================================]"
ufw status verbose