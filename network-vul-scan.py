"""
Simple Network Vulnerability Scanner

- Scans a target host for open TCP ports.
- Flags ports commonly associated with vulnerabilities.
- Provides a simple report.

Usage:
    python simple_network_vulnerability_scanner.py

Dependencies:
    (Python standard library only)
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports and associated risks (for demonstration)
VULN_PORTS = {
    21: "FTP (often insecure, supports anonymous access, unencrypted)",
    22: "SSH (check for weak credentials, outdated versions)",
    23: "Telnet (unencrypted, obsolete, high risk)",
    25: "SMTP (can be abused for spam/relay)",
    80: "HTTP (look for outdated web servers, exploits)",
    110: "POP3 (unencrypted, weak authentication)",
    139: "NetBIOS (Windows file sharing, can leak info)",
    143: "IMAP (unencrypted, weak authentication)",
    443: "HTTPS (check for weak SSL/TLS configs)",
    445: "SMB (Windows file sharing, vulnerable to many worms)",
    3389: "RDP (remote desktop, brute force risk, exploits)",
}

def scan_port(host, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return port if result == 0 else None
    except Exception:
        return None

def main():
    print("=== Simple Network Vulnerability Scanner ===")
    target = input("Target IP address or hostname: ").strip()
    start_port = int(input("Start port (default 1): ") or 1)
    end_port = int(input("End port (default 65536): ") or 65536)
    max_workers = 100

    print(f"Scanning {target} ports {start_port}-{end_port}...")
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, target, port): port for port in range(start_port, end_port + 1)}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            result = future.result()
            if result is not None:
                open_ports.append(result)
                print(f"Port {result} is OPEN")

    print("\n=== Vulnerability Scan Report ===")
    if not open_ports:
        print("No open ports found.")
    else:
        for port in sorted(open_ports):
            service = VULN_PORTS.get(port)
            if service:
                print(f"[!] Port {port}: {service}")
            else:
                print(f"[*] Port {port}: (Unknown - no specific mapping)")

    print("\nScan complete. Use responsibly.")

if __name__ == "__main__":
    main()