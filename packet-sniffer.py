from scapy.all import sniff
import time

def packet_callback(packet):
    with open("sniffer.log", "a", encoding="utf-8") as f:
        f.write(str(time.strftime("%Y-%m-%d %H:%M:%S")) + " - " + str(packet) + "\n")

def main():
    print("Starting packet capture... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, count=0)  # count=0 means unlimited until stopped

if __name__ == "__main__":
    main()
