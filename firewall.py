"""
Simple User-Space Firewall (Linux, Python, Educational)

- Filters TCP packets by source/destination IP and port.
- Logs allowed and blocked packets.
- Uses scapy for packet sniffing.
- Requires root privileges to sniff packets.

Dependencies:
    pip install scapy

For actual blocking, integrate with iptables or use OS-provided tools.
"""

from scapy.all import sniff, IP, TCP
import time
import psutil

# Define rules: (ip, port) pairs to block or allow
BLOCKED_IPS = {'192.168.1.100'}
BLOCKED_PORTS = {23, 4444}

ALLOWED_IPS = {'8.8.8.8'}
ALLOWED_PORTS = {80, 443}

def packet_filter(pkt):
    # Only process TCP/IP packets
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport

        action = "ALLOW"

        # Block if source/destination IP or port is in blocked list
        if src_ip in BLOCKED_IPS or dst_ip in BLOCKED_IPS:
            action = "BLOCK"
        if src_port in BLOCKED_PORTS or dst_port in BLOCKED_PORTS:
            action = "BLOCK"
        # Allow if in allowed lists (overrides block for demo purposes)
        if src_ip in ALLOWED_IPS or dst_ip in ALLOWED_IPS:
            action = "ALLOW"
        if src_port in ALLOWED_PORTS or dst_port in ALLOWED_PORTS:
            action = "ALLOW"

        # Log the event
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {action}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        # To actually block, you would drop the packet here (requires OS integration)
        # In user-space, we can only log or trigger an external block (e.g., modify iptables)
        # Optionally, trigger system commands for actual blocking (advanced)
    # else: Ignore non-TCP/IP packets

def show_open_ports_and_processes():
    print("Ports ouverts et connexions actives :")
    ports_info = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == "LISTEN":
            pid = conn.pid
            proc_name = "Unknown"
            if pid:
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                except Exception:
                    pass
            ports_info.append((conn.laddr.ip, conn.laddr.port, proc_name, pid))
    for ip, port, proc_name, pid in sorted(ports_info, key=lambda x: x[1]):
        print(f"Port {port} (IP {ip}) ouvert par {proc_name} (PID {pid})")
    print()

def prompt_block_rule():
    print("\nVoulez-vous bloquer un port ou une IP ?")
    print("Tapez 'port' pour bloquer un port, 'ip' pour bloquer une IP, ou 'non' pour continuer.")
    choix = input("Votre choix : ").strip().lower()
    if choix == "port":
        port = input("Numéro du port à bloquer : ").strip()
        try:
            port = int(port)
            BLOCKED_PORTS.add(port)
            print(f"Port {port} ajouté à la liste des ports bloqués.")
        except ValueError:
            print("Numéro de port invalide.")
    elif choix == "ip":
        ip = input("Adresse IP à bloquer : ").strip()
        BLOCKED_IPS.add(ip)
        print(f"IP {ip} ajoutée à la liste des IP bloquées.")
    else:
        print("Aucune règle ajoutée.")

def main():
    show_open_ports_and_processes()
    prompt_block_rule()
    print("Starting simple firewall (monitor mode)... Press Ctrl+C to stop.")
    print("Blocked IPs:", BLOCKED_IPS)
    print("Blocked Ports:", BLOCKED_PORTS)
    sniff(prn=packet_filter, store=0)

if __name__ == "__main__":
    main()