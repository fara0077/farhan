import argparse
import socket
from rich.console import Console
from rich.table import Table

BLOCKLIST = {"1.2.3.4", "5.6.7.8", "192.168.1.1"}

socket.setdefaulttimeout(3)

parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file', required=True)
args = parser.parse_args()

filename = args.file

try:
    file = open(filename, 'r')
    lines = file.readlines()
    file.close()
except FileNotFoundError:
    print(f"Error: File '{filename}' not found.")
    exit()

ips = []
for line in lines:
    clean_ip = line.strip()
    if clean_ip:
        ips.append(clean_ip)

console = Console()
table = Table(title="IP Threat Check Results")
table.add_column("IP")
table.add_column("Reverse DNS")
table.add_column("In Blocklist")
table.add_column("Risk Level")

for ip in ips:
    try:
        socket.inet_aton(ip)
    except OSError:
        table.add_row(ip, "Invalid IP", "N/A", "N/A")
        continue

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except socket.herror:
        hostname = "No PTR record"
    except socket.timeout:
        hostname = "DNS Timeout"

    if ip in BLOCKLIST:
        in_blocklist = "YES"
    else:
        in_blocklist = "NO"

    if in_blocklist == "YES":
        risk = "High"
    elif hostname == "No PTR record":
        risk = "Medium"
    else:
        risk = "Low"

    table.add_row(ip, hostname, in_blocklist, risk)

console.print(table)
