import nmap

def scan_services_on_ports(target_host):
    """
    Scanne un hôte cible pour identifier les services exécutés sur chaque port ouvert.

    Args:
        target_host (str): L'adresse IP ou le nom d'hôte de la cible à scanner.
    """
    nm = nmap.PortScanner()

    try:
        print(f"[*] Démarrage du scan de {target_host}...")
        # Scanne tous les ports TCP courants (par défaut, Nmap en scanne 1000)
        # '-sV' active la détection de version de service
        nm.scan(hosts=target_host, arguments='-sV')

        if target_host not in nm.all_hosts():
            print(f"[-] L'hôte {target_host} n'est pas atteignable ou aucune information n'a été trouvée.")
            return

        for host in nm.all_hosts():
            print(f"\n[+] Résultats du scan pour l'hôte : {host} ({nm[host].hostname()})")
            print(f"    État : {nm[host].state()}")

            if 'tcp' in nm[host]:
                print("\n    Ports TCP ouverts et services :")
                for port in sorted(nm[host]['tcp']):
                    port_info = nm[host]['tcp'][port]
                    print(f"        Port : {port}")
                    print(f"            État    : {port_info['state']}")
                    print(f"            Service : {port_info['name']}")
                    print(f"            Produit : {port_info['product']}")
                    print(f"            Version : {port_info['version']}")
                    print(f"            Extra   : {port_info['extrainfo']}")
            else:
                print("\n    Aucun port TCP ouvert trouvé.")

    except nmap.nmap.PortScannerError as e:
        print(f"[-] Erreur Nmap : {e}")
        print("    Assurez-vous que Nmap est installé et que vous avez les permissions nécessaires (ex: sudo).")
    except Exception as e:
        print(f"[-] Une erreur inattendue s'est produite : {e}")

if __name__ == "__main__":
    # Exemple d'utilisation :
    # Remplacez '127.0.0.1' par l'adresse IP ou le nom d'hôte que vous souhaitez scanner.
    # Soyez conscient des lois et réglementations concernant les scans de réseau.
    # Ne scannez que les systèmes pour lesquels vous avez l'autorisation explicite.
    target = input("Veuillez entrer l'adresse IP ou le nom d'hôte cible : ")
    scan_services_on_ports(target)