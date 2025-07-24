from scapy.all import sniff, IP, TCP, UDP, Raw
import time
from datetime import datetime

def packet_callback(packet):
    log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - "

    # Exemple d'analyse des couches
    if packet.haslayer(IP):
        log_entry += f"Source IP: {packet[IP].src}, Dest IP: {packet[IP].dst}"
        if packet.haslayer(TCP):
            log_entry += f", Protocol: TCP, Source Port: {packet[TCP].sport}, Dest Port: {packet[TCP].dport}"
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                log_entry += " (HTTP Traffic)"
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                log_entry += " (HTTPS Traffic)"
        elif packet.haslayer(UDP):
            log_entry += f", Protocol: UDP, Source Port: {packet[UDP].sport}, Dest Port: {packet[UDP].dport}"
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                log_entry += " (DNS Traffic)"

        # Essayer d'extraire des données brutes si présentes
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                # Ne pas logguer des payloads entiers sauf si c'est nécessaire pour éviter les logs géants
                log_entry += f", Payload (extrait): {payload[:50]}..." 
            except:
                pass # Ignore les erreurs de décodage

    with open("sniffer.log", "a", encoding="utf-8") as f:
        f.write(log_entry + "\n")