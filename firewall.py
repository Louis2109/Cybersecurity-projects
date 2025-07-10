"""
Firewall Python Simple (User-Space)

Rôle d'un firewall :
--------------------
Un firewall (pare-feu) est un système de sécurité réseau qui surveille, filtre et contrôle le trafic réseau entrant et sortant selon des règles prédéfinies. Il protège un ordinateur ou un réseau contre les accès non autorisés, les attaques et les communications indésirables.

Fonctionnalités de ce programme :
---------------------------------
- Filtrage des paquets TCP/IP selon l'adresse IP source/destination et le port.
- Blocage ou autorisation du trafic selon des listes d'IP et de ports bloqués/autorisés.
- Journalisation (logging) de chaque paquet traité (autorisé ou bloqué) dans un fichier 'firewall.log'.
- Affichage des ports ouverts et des processus associés sur la machine.
- Menu interactif pour ajouter dynamiquement des règles de blocage (IP ou port).
- Utilisation de Scapy pour l'analyse des paquets réseau (mode surveillance).
- Ce programme fonctionne en espace utilisateur (user-space) et ne bloque pas réellement les paquets au niveau système, mais il peut être adapté pour interagir avec des outils système (iptables, netsh, etc.) pour un blocage effectif.

Dépendances :
-------------
- scapy
- psutil

Usage :
-------
    pip install scapy psutil
    python firewall.py

Note :
------
Pour un blocage réel des paquets, il est nécessaire d'intégrer ce script avec des outils système adaptés à votre OS.
"""

# ###### Guide moi à implementer les étapes
# Étape 3 : Menu interactif
# Proposer un menu pour :
# Ajouter une règle
# Supprimer une règle
# Lister les règles
# Quitter

# Étape 4 : (Avancé) Blocage réel
# Pour un vrai blocage, intégrer des commandes système :
# Sous Linux : utiliser iptables via os.system() ou subprocess.
# Sous Windows : utiliser netsh ou le pare-feu Windows.

# Étape 5 : Filtrage avancé
# Ajouter le support UDP/ICMP.
# Permettre le filtrage par plage d’IP ou sous-réseau.






from scapy.all import sniff, IP, TCP
import time
import psutil
import json

# Define rules: (ip, port) pairs to block or allow
BLOCKED_IPS = {'192.168.1.100'}
BLOCKED_PORTS = {23, 4444}

ALLOWED_IPS = {'8.8.8.8'}
ALLOWED_PORTS = {80, 443}

RULES_FILE = "firewall_rules.json"

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

        log_msg = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {action}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        print(log_msg)
        log_event(log_msg)

        # To actually block, you would drop the packet here (requires OS integration)
        # In user-space, we can only log or trigger an external block (e.g., modify iptables)
        # Optionally, trigger system commands for actual blocking (advanced)
    # else: Ignore non-TCP/IP packets

def log_event(message):
    with open("firewall.log", "a", encoding="utf-8") as f:
        f.write(message + "\n")

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
            save_rules()
            print(f"Port {port} ajouté à la liste des ports bloqués.")
        except ValueError:
            print("Numéro de port invalide.")
    elif choix == "ip":
        ip = input("Adresse IP à bloquer : ").strip()
        BLOCKED_IPS.add(ip)
        save_rules()
        print(f"IP {ip} ajoutée à la liste des IP bloquées.")
    else:
        print("Aucune règle ajoutée.")

def save_rules():
    rules = {
        "BLOCKED_IPS": list(BLOCKED_IPS),
        "BLOCKED_PORTS": list(BLOCKED_PORTS),
        "ALLOWED_IPS": list(ALLOWED_IPS),
        "ALLOWED_PORTS": list(ALLOWED_PORTS)
    }
    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2)

def load_rules():
    global BLOCKED_IPS, BLOCKED_PORTS, ALLOWED_IPS, ALLOWED_PORTS
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            rules = json.load(f)
            BLOCKED_IPS = set(rules.get("BLOCKED_IPS", []))
            BLOCKED_PORTS = set(rules.get("BLOCKED_PORTS", []))
            ALLOWED_IPS = set(rules.get("ALLOWED_IPS", []))
            ALLOWED_PORTS = set(rules.get("ALLOWED_PORTS", []))
    except FileNotFoundError:
        pass  # Fichier absent, on garde les valeurs par défaut

def main():
    load_rules()
    show_open_ports_and_processes()
    prompt_block_rule()
    print("Starting simple firewall (monitor mode)... Press Ctrl+C to stop.")
    print("Blocked IPs:", BLOCKED_IPS)
    print("Blocked Ports:", BLOCKED_PORTS)
    sniff(prn=packet_filter, store=0)

if __name__ == "__main__":
    main()