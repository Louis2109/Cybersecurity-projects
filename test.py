import nmap

def scan_with_nmap_service_detection(target, ports_range_str):
    """
    Scans a target for open ports and identifies services using Nmap's -sV option.
    :param target: The IP address or hostname to scan.
    :param ports_range_str: A string representing the port range (e.g., "1-1024", "80,443").
    :return: A list of strings, each describing an open port and its detected service.
    """
    nm = nmap.PortScanner()
    
    try:
        # -sV: Enables service version detection (more detailed and accurate)
        # -p: Specifies the port range
        # --open: Only show ports that are identified as open
        # -T4: Sets the timing template (higher is faster, can be more detectable)
        print(f"[*] Lancement du scan Nmap sur {target} pour les ports {ports_range_str}...")
        nm.scan(target, arguments=f'-sV -p {ports_range_str} --open -T4')
    except nmap.PortScannerError as e:
        return [f"Erreur Nmap: {e}. Assurez-vous que Nmap est installé et accessible via la variable PATH."]
    except Exception as e:
        return [f"Une erreur inattendue est survenue lors du scan Nmap: {e}"]

    detected_services = []
    # Loop through all scanned hosts (usually just one in your case)
    for host in nm.all_hosts():
        # Check if the host is up and details are available
        if nm[host].state() == 'up':
            # Iterate through all protocols Nmap found (e.g., 'tcp', 'udp')
            for proto in nm[host].all_protocols():
                # Get the list of ports for the current protocol
                ports = nm[host][proto].keys()
                # Sort ports for cleaner output
                for port in sorted(ports):
                    # Check if the port state is 'open'
                    if nm[host][proto][port]['state'] == 'open':
                        service_name = nm[host][proto][port].get('name', 'unknown')
                        product = nm[host][proto][port].get('product', '')
                        version = nm[host][proto][port].get('version', '')
                        extrainfo = nm[host][proto][port].get('extrainfo', '')
                        
                        description = f"Service: {service_name}"
                        if product:
                            description += f", Produit: {product}"
                        if version:
                            description += f", Version: {version}"
                        if extrainfo:
                            description += f", Info supp: {extrainfo}"
                        
                        detected_services.append(f"Port {port}/{proto} est OUVERT - {description}")
    
    if not detected_services:
        detected_services.append("Aucun port ouvert avec des services identifiables trouvé dans la plage spécifiée.")

    return detected_services

if __name__ == "__main__":
    # --- Instructions de test ---
    print("--- Test du scanner de service Nmap ---")
    print("Assurez-vous que Nmap est installé sur votre système (https://nmap.org/download.html).")
    print("Et que la bibliothèque Python 'python-nmap' est installée: pip install python-nmap\n")
    
    # Demande à l'utilisateur la cible et la plage de ports
    target_ip = input("Entrez l'adresse IP ou le nom d'hôte cible (ex: scanme.nmap.org ou 127.0.0.1): ").strip()
    ports_range = input("Entrez la plage de ports (ex: 1-1000, 20-25, 80,443): ").strip()
    
    if not target_ip:
        print("Cible non spécifiée. Utilisation de 'scanme.nmap.org' par défaut.")
        target_ip = "scanme.nmap.org"
    
    if not ports_range:
        print("Plage de ports non spécifiée. Utilisation de '20-25,80' par défaut pour un test rapide.")
        ports_range = "20-25,80" # Petite plage pour un test rapide

    print(f"\nScanning {target_ip} for ports {ports_range}...")
    
    # Appel de la fonction de scan
    results = scan_with_nmap_service_detection(target_ip, ports_range)
    
    print("\n--- Résultats du Scan ---")
    for line in results:
        print(line)
    print("\n--- Fin du test ---")