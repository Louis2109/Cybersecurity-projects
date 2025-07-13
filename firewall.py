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

def list_rules():
    print("\n--- Règles Actuelles ---")
    print("IPs Bloquées  :", sorted(list(BLOCKED_IPS)))
    print("Ports Bloqués :", sorted(list(BLOCKED_PORTS)))
    print("IPs Autorisées:", sorted(list(ALLOWED_IPS)))
    print("Ports Autorisés:", sorted(list(ALLOWED_PORTS)))
    print("-----------------------\n")
    print("#############    Le firewall est lancé.....    ############ \n## Aller dans le fichier firewall.log pour voir les événements. \n## Appuyez sur Ctrl+C pour arrêter.")
    

def add_rule():
    rule_type = input("Type de règle (block/allow): ").strip().lower()
    if rule_type not in ['block', 'allow']:
        print("Type invalide. Choisissez 'block' ou 'allow'.")
        return

    target_type = input("Cible de la règle (ip/port): ").strip().lower()
    if target_type not in ['ip', 'port']:
        print("Cible invalide. Choisissez 'ip' ou 'port'.")
        return

    value = input(f"Entrez l'{'adresse IP' if target_type == 'ip' else 'numéro de port'} à {rule_type}: ").strip()

    if target_type == 'port':
        try:
            value = int(value)
        except ValueError:
            print("Erreur: Le numéro de port doit être un entier.")
            return

    target_set = None
    if rule_type == 'block':
        target_set = BLOCKED_IPS if target_type == 'ip' else BLOCKED_PORTS
    else: # allow
        target_set = ALLOWED_IPS if target_type == 'ip' else ALLOWED_PORTS

    target_set.add(value)
    save_rules()
    print(f"Règle ajoutée: {rule_type.upper()} {target_type.upper()} {value}")

def remove_rule():
    rule_type = input("Type de règle à supprimer (block/allow): ").strip().lower()
    if rule_type not in ['block', 'allow']:
        print("Type invalide. Choisissez 'block' ou 'allow'.")
        return

    target_type = input("Cible de la règle à supprimer (ip/port): ").strip().lower()
    if target_type not in ['ip', 'port']:
        print("Cible invalide. Choisissez 'ip' ou 'port'.")
        return

    value = input(f"Entrez l'{'adresse IP' if target_type == 'ip' else 'numéro de port'} à supprimer: ").strip()

    if target_type == 'port':
        try:
            value = int(value)
        except ValueError:
            print("Erreur: Le numéro de port doit être un entier.")
            return

    target_set = None
    if rule_type == 'block':
        target_set = BLOCKED_IPS if target_type == 'ip' else BLOCKED_PORTS
    else: # allow
        target_set = ALLOWED_IPS if target_type == 'ip' else ALLOWED_PORTS

    if value in target_set:
        target_set.remove(value)
        save_rules()
        print(f"Règle supprimée: {rule_type.upper()} {target_type.upper()} {value}")
    else:
        print(f"Erreur: La règle '{value}' n'existe pas dans la liste.")

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

def interactive_menu():
    while True:
        print("\n--- Menu du Pare-feu ---")
        print("1. Lister les règles")
        print("2. Ajouter une règle")
        print("3. Supprimer une règle")
        print("4. Lancer le pare-feu (mode surveillance)")
        print("5. Quitter")
        choice = input("Votre choix : ").strip()

        if choice == '1':
            list_rules()
        elif choice == '2':
            add_rule()
        elif choice == '3':
            remove_rule()
        elif choice == '4':
            return True # Proceed to start firewall
        elif choice == '5':
            return False # Exit program
        else:
            print("Choix invalide, veuillez réessayer.")

def main():
    load_rules()
    show_open_ports_and_processes()
    if interactive_menu():
        print("\nLancement du pare-feu (mode surveillance)... Appuyez sur Ctrl+C pour arrêter.")
        list_rules()
        sniff(prn=packet_filter, store=0)
    else:
        print("Arrêt du programme.")

if __name__ == "__main__":
    main()
