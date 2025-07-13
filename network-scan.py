"""
Network Vulnerability Scanner with Telegram Reporting

- Scans a target host for open TCP ports
- Logs scan results to scan.log
- Sends scan results via Telegram
"""

import socket
import nmap # Il faut add une focntion qui va identifier les service qui tourne sur les ports.
from concurrent.futures import ThreadPoolExecutor, as_completed
import telegram
import asyncio
import time

# Configuration Telegram
TELEGRAM_BOT_TOKEN = "8018867438:AAFPnVkkSuND4R1bbqU5B6lDiAFFJFWQoKI"
TELEGRAM_CHAT_ID = "5622778224"

# Configuration globale
CURRENT_TIME = time.strftime("%Y-%m-%d %H:%M:%S")

# Services communs et leurs descriptions
COMMON_SERVICES = {
    20: "FTP-DATA - File Transfer Protocol (Data)",
    21: "FTP - File Transfer Protocol",
    22: "SSH - Secure Shell",
    23: "Telnet - Remote Login Service",
    25: "SMTP - Simple Mail Transfer Protocol",
    53: "DNS - Domain Name System",
    80: "HTTP - HyperText Transfer Protocol",
    110: "POP3 - Post Office Protocol v3",
    115: "SFTP - Secure File Transfer Protocol",
    143: "IMAP - Internet Message Access Protocol",
    443: "HTTPS - HTTP over TLS/SSL",
    445: "SMB - Server Message Block",
    3389: "RDP - Remote Desktop Protocol",
    8080: "HTTP-ALT - Alternative HTTP Port"
}

# Ajoutez ces fonctions au début du code
async def get_telegram_username():
    """Récupère le nom d'utilisateur Telegram"""
    try:
        bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)
        chat = await bot.get_chat(chat_id=TELEGRAM_CHAT_ID)
        return chat.username or "User telegram"
    except Exception as e:
        print(f"Erreur lors de la récupération du nom d'utilisateur Telegram: {e}")
        return "Unknown User"

def get_service_description(port):
    return COMMON_SERVICES.get(port, "Unknown Service")

def scan_port(host, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return port if result == 0 else None
    except Exception:
        return None

async def send_telegram_alert(scan_file, scan_start, scan_end):
    """Envoie le fichier de scan via Telegram"""
    try:
        bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)    
        # Message initial
        await bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text=f"🔍 Nouveau Scan de Vulnérabilité\n"
                 f"- Date: {CURRENT_TIME}\n"
                 f"- User: {CURRENT_USER}\n"
                 f"- App: {CURRENT_APP}\n"
                 f"- Port Range: {scan_start}-{scan_end}\n\n"
                 f"📄 Résultats du scan ci-dessous ⬇️"
        )

        # Envoi du fichier
        with open(scan_file, 'rb') as f:
            await bot.send_document(
                chat_id=TELEGRAM_CHAT_ID,
                document=f,
                caption="Rapport de scan détaillé"
            )
        
        print("Résultats du scan envoyés sur Telegram avec succès!")
    except Exception as e:
        print(f"Erreur lors de l'envoi Telegram: {e}")

def write_scan_log(target, open_ports, scan_start, scan_end):
    """Écrit les résultats du scan dans un fichier log"""
    log_file = 'scan.log'
    
    with open(log_file, 'w', encoding='utf-8') as f:
        f.write(f"Network Vulnerability Scan Report\n") 
        f.write(f"{'='*50}\n\n") 
        f.write(f"Scan Details:\n") 
        f.write(f"- Target: {target}\n") 
        f.write(f"- Date: {CURRENT_TIME}\n") 
        f.write(f"- User: {CURRENT_USER}\n") 
        f.write(f"- App: {CURRENT_APP}\n") 
        f.write(f"- Port Range: {scan_start}-{scan_end}\n\n") 
        f.write(f"Open Ports:\n") 
        f.write(f"{'-'*50}\n\n") 

        if open_ports:
            for port in sorted(open_ports):
                service = get_service_description(port)
                f.write(f"Port {port} is OPEN - {service}\n") 
        else:
            f.write("No open ports found.\n") 
    
    return log_file

async def main(): 
    global CURRENT_USER, CURRENT_APP, start_port, end_port
    
    # Récupérer le nom d'utilisateur Telegram
    CURRENT_USER = await get_telegram_username()
    
    print("=== Network Vulnerability Scanner with Telegram Reporting ===")
    target = input("Target IP address or hostname: ").strip()
    CURRENT_APP = target  # Stocke le hostname cible
    start_port = int(input("Start port (default 1): ") or 1)
    end_port = int(input("End port (default 65536): ") or 65536)
    max_workers = 100

    print(f"\n[*] Scanning {target} ports {start_port}-{end_port}...")
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, target, port): port 
            for port in range(start_port, end_port + 1)
        }
        
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            result = future.result()
            if result is not None:
                open_ports.append(result)
                print(f"Port {result} is OPEN - {get_service_description(result)}")

    # Écriture du fichier log
    log_file = write_scan_log(target, open_ports, start_port, end_port)
    
    # Envoi du rapport sur Telegram
    print("\n[*] Envoi du rapport sur Telegram...")
    await send_telegram_alert(log_file, start_port, end_port) # Corrected: Added scan_start and scan_end arguments
    
    print(f"\n[+] Scan complete. Results saved to '{log_file}' and sent to Telegram.")

if __name__ == "__main__":
    asyncio.run(main())