from scapy.all import sniff

def packet_callback(packet):
    with open("packets.log", "a", encoding="utf-8") as f:
        f.write(packet.summary() + "\n")

def main():
    print("Starting packet capture... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, count=0)  # count=0 means unlimited until stopped

if __name__ == "__main__":
    main()
