#!/usr/bin/python3

import socket
import sys
import threading
import json
import csv
import time
from tqdm import tqdm
#Gargi pagal h

# Usage information
usage = "Usage: python3 port_scan.py TARGET START_PORT END_PORT [--open | --filtered | --closed | --export <format>]"

help_message = """
Advanced Python Port Scanner

Usage:
    python3 port_scan.py TARGET START_PORT END_PORT [OPTION]

Arguments:
    TARGET      - IP address or domain to scan
    START_PORT  - Starting port number
    END_PORT    - Ending port number

Options:
    --open          - Show only open ports
    --filtered      - Show only filtered ports
    --closed        - Show only closed ports
    --export txt    - Save results to a .txt file
    --export csv    - Save results to a .csv file
    --export json   - Save results to a .json file
    --help          - Show this help message

Example:
    python3 port_scan.py 192.168.1.1 1 100 --open --export json
"""

print("-" * 70)
print("Advanced Python Port Scanner")
print("-" * 70)

# Check if the correct arguments are provided
if len(sys.argv) < 4 or len(sys.argv) > 6:
    if len(sys.argv) == 2 and sys.argv[1] == "--help":
        print(help_message)
    else:
        print(usage)
    sys.exit()

# Resolve target IP address
try:
    target = socket.gethostbyname(sys.argv[1])
except socket.gaierror:
    print("Name resolution error")
    sys.exit()

start_port = int(sys.argv[2])
end_port = int(sys.argv[3])
filter_option = None
export_option = None

if len(sys.argv) >= 5:
    if sys.argv[4] in ["--open", "--filtered", "--closed"]:
        filter_option = sys.argv[4]
    elif sys.argv[4] == "--export" and len(sys.argv) == 6:
        export_option = sys.argv[5]
    else:
        print("Invalid option!")
        sys.exit()

print("Scanning target:", target)

# Common ports and their services
port_services = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP-Proxy"
}

open_ports = []
filtered_ports = []
closed_ports = []

def detect_service(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((target, port))
        s.send(b'\n')
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner if banner else "Unknown Version"
    except:
        return "Unknown Version"

def scan_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)  # Timeout for faster scanning
    try:
        conn = s.connect_ex((target, port))
        service = port_services.get(port, "Unknown Service")
        version = detect_service(port) if conn == 0 else ""
       
        if conn == 0:
            open_ports.append((port, service, version))
        elif conn == 11:  # 11 is an indicative error code for filtered ports
            filtered_ports.append((port, service))
        else:
            closed_ports.append((port, service))
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
    finally:
        s.close()

# Launch threads to scan ports with progress bar
threads = []
for port in tqdm(range(start_port, end_port + 1), desc="Scanning Ports"):
    thread = threading.Thread(target=scan_port, args=(port,))
    thread.start()
    threads.append(thread)

# Wait for all threads to finish
for thread in threads:
    thread.join()

# Display results based on filter option
if filter_option == "--open" or filter_option is None:
    if open_ports:
        print("\nOpen Ports:")
        for port, service, version in open_ports:
            print(f"  - Port {port} ({service}) - {version}")
    else:
        print("\nNo open ports found.")

if filter_option == "--filtered":
    if filtered_ports:
        print("\nFiltered Ports:")
        for port, service in filtered_ports:
            print(f"  - Port {port} ({service}) is FILTERED")
    else:
        print("\nNo filtered ports found.")

if filter_option == "--closed":
    if closed_ports:
        print("\nClosed Ports:")
        for port, service in closed_ports:
            print(f"  - Port {port} ({service}) is CLOSED")
    else:
        print("\nNo closed ports found.")

# Export results if requested
def export_results():
    filename = f"scan_results.{export_option}"
    if export_option == "txt":
        with open(filename, "w") as f:
            f.write(f"Open Ports: {open_ports}\nFiltered Ports: {filtered_ports}\nClosed Ports: {closed_ports}\n")
    elif export_option == "csv":
        with open(filename, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Port", "Service", "Status", "Version"])
            for port, service, version in open_ports:
                writer.writerow([port, service, "Open", version])
    elif export_option == "json":
        data = {"open_ports": open_ports, "filtered_ports": filtered_ports, "closed_ports": closed_ports}
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
    print(f"Results exported to {filename}")

if export_option:
    export_results()
