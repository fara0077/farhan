"""
ioc_enricher.py

A command-line IOC (Indicator of Compromise) enrichment tool.
Accepts a single IP, a single file hash, a single URL, a single domain,
OR a text file full of IPs, and enriches each one using 4 real threat
intelligence services: VirusTotal, AbuseIPDB, Shodan, and AlienVault OTX.

Usage examples:
    python ioc_enricher.py --ip 8.8.8.8
    python ioc_enricher.py --hash 44d88612fea8a8f36de82e1278abb02f
    python ioc_enricher.py --url http://example.com
    python ioc_enricher.py --domain example.com
    python ioc_enricher.py -f ips.txt
"""
from config import VT_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY, OTX_API_KEY
from rich.console import Console
from rich.table import Table
import argparse
import socket
import requests
import shodan
import time
import base64


# ---------------------------------------------------------------------------
# Exponential backoff wrapper — used by VirusTotal and AbuseIPDB requests to
# gracefully handle rate limiting (HTTP 429) instead of failing immediately.
# ---------------------------------------------------------------------------
def make_request_with_backoff(url, headers, params=None, max_retries=5):
    for attempt in range(max_retries):
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response
        elif response.status_code == 429:
            wait_time = 2 ** attempt
            print(f"Rate limited. Waiting {wait_time}s before retry...")
            time.sleep(wait_time)
        else:
            return response
    return response


# ---------------------------------------------------------------------------
# Hardcoded blocklist — simulates a simple internal threat intel feed.
# ---------------------------------------------------------------------------
BLOCKLIST = {"1.2.3.4", "5.6.7.8", "192.168.1.1"}


# ---------------------------------------------------------------------------
# VirusTotal — IP, file hash, URL, and domain lookups
# Each IOC type has its own dedicated VirusTotal endpoint.
# ---------------------------------------------------------------------------


def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = make_request_with_backoff(url, headers)
    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return stats


def check_virustotal_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    response = make_request_with_backoff(url, headers)
    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return stats


def check_virustotal_url(url_to_check):
    # VirusTotal needs the URL itself encoded into a safe, ID-like string
    # before it can be used as part of the lookup web address.
    url_id = base64.urlsafe_b64encode(
        url_to_check.encode()).decode().strip("=")
    lookup_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}
    response = make_request_with_backoff(lookup_url, headers)
    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return stats


def check_virustotal_domain(domain):
    # Domains use their own dedicated endpoint (richer than the URL one —
    # includes things like WHOIS/registration data alongside detections).
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    response = make_request_with_backoff(url, headers)
    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return stats


# ---------------------------------------------------------------------------
# AbuseIPDB — IP reputation score (0-100)
# ---------------------------------------------------------------------------


def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip}
    response = make_request_with_backoff(url, headers, params=params)
    data = response.json()
    score = data["data"]["abuseConfidenceScore"]
    return score


# ---------------------------------------------------------------------------
# Shodan — open ports / ISP info for an IP
# Note: free "oss" tier has 0 query credits for fresh scans, but lookups
# for well-known, heavily-indexed IPs (e.g. major DNS providers) still
# succeed in testing. Lesser-known IPs may return an APIError.
# ---------------------------------------------------------------------------


def check_shodan(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        result = api.host(ip)
        ports = result.get("ports", [])
        isp = result.get("isp", "Unknown")
        ports_text = ",".join(str(p) for p in ports)
        return f"{len(ports)} ports ({ports_text}), {isp}"
    except shodan.APIError as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# AlienVault OTX — community threat pulse count for an IP
# ---------------------------------------------------------------------------


def check_otx(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return 0
        data = response.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return pulse_count
    except requests.exceptions.JSONDecodeError:
        return 0


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------
def is_valid_ip(value):
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False


def is_file_hash(value):
    if len(value) in (32, 40, 64) and value.isalnum():
        return True
    return False


# ---------------------------------------------------------------------------
# Reusable function: enrich ONE ip and return a row of values.
# Used by both the single --ip mode and the -f file mode, so the logic
# only needs to be written once.
# ---------------------------------------------------------------------------
def enrich_ip(ip):
    try:
        socket.inet_aton(ip)
    except OSError:
        return [ip, "Invalid IP", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"]

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except socket.herror:
        hostname = "No PTR record"
    except socket.timeout:
        hostname = "DNS Timeout"

    in_blocklist = "YES" if ip in BLOCKLIST else "NO"

    vt_stats = check_virustotal(ip)
    malicious = vt_stats["malicious"]
    vt_display = f"{malicious} malicious"

    abuse_score = check_abuseipdb(ip)
    shodan_info = check_shodan(ip)
    otx_pulses = check_otx(ip)

    if in_blocklist == "YES" or malicious > 0 or abuse_score > 50 or otx_pulses > 5:
        risk = "High"
    elif hostname == "No PTR record":
        risk = "Medium"
    else:
        risk = "Low"

    return [ip, hostname, in_blocklist, vt_display, str(abuse_score), shodan_info, str(otx_pulses), risk]


# ---------------------------------------------------------------------------
# Small reusable helper: print a simple 4-column VT-stats table
# (used identically by --hash, --url, and --domain modes).
# ---------------------------------------------------------------------------
def print_vt_stats_table(title, id_column_name, id_value, stats):
    console = Console()
    table = Table(title=title)
    table.add_column(id_column_name)
    table.add_column("Malicious")
    table.add_column("Suspicious")
    table.add_column("Harmless")
    table.add_row(
        id_value,
        str(stats["malicious"]),
        str(stats["suspicious"]),
        str(stats["harmless"]),
    )
    console.print(table)


# ---------------------------------------------------------------------------
# Command-line argument setup — 5 mutually usable modes:
#   -f/--file   : a text file full of IPs (one per line)
#   --ip        : a single IP address
#   --hash      : a single file hash (MD5/SHA1/SHA256)
#   --url       : a single full URL
#   --domain    : a single bare domain name
# ---------------------------------------------------------------------------
socket.setdefaulttimeout(3)

parser = argparse.ArgumentParser(
    description="IOC enrichment tool - IPs, hashes, URLs, and domains")
parser.add_argument('-f', '--file', required=False,
                    help="Text file containing IP addresses, one per line")
parser.add_argument('--ip', required=False,
                    help="A single IP address to check")
parser.add_argument('--hash', required=False,
                    help="A single file hash (MD5/SHA1/SHA256) to check")
parser.add_argument('--url', required=False, help="A single full URL to check")
parser.add_argument('--domain', required=False,
                    help="A single bare domain name to check")
args = parser.parse_args()

if not args.file and not args.ip and not args.hash and not args.url and not args.domain:
    print("Error: provide one of -f <file>, --ip <ip>, --hash <hash>, --url <url>, or --domain <domain>")
    exit()


# ---------------------------------------------------------------------------
# Mode: --hash  (single file hash lookup)
# ---------------------------------------------------------------------------
if args.hash:
    stats = check_virustotal_hash(args.hash)
    print_vt_stats_table("File Hash Enrichment Result",
                         "Hash", args.hash, stats)
    exit()


# ---------------------------------------------------------------------------
# Mode: --url  (single full URL lookup)
# ---------------------------------------------------------------------------
if args.url:
    stats = check_virustotal_url(args.url)
    print_vt_stats_table("URL Enrichment Result", "URL", args.url, stats)
    exit()


# ---------------------------------------------------------------------------
# Mode: --domain  (single bare domain lookup — dedicated domain endpoint)
# ---------------------------------------------------------------------------
if args.domain:
    stats = check_virustotal_domain(args.domain)
    print_vt_stats_table("Domain Enrichment Result",
                         "Domain", args.domain, stats)
    exit()


# ---------------------------------------------------------------------------
# Mode: --ip  (single IP, no file needed)
# ---------------------------------------------------------------------------
if args.ip:
    console = Console()
    table = Table(title="Single IP Enrichment Result")
    table.add_column("IP")
    table.add_column("Reverse DNS")
    table.add_column("In Blocklist")
    table.add_column("VT Detection")
    table.add_column("AbuseIPDB Score")
    table.add_column("Shodan Info")
    table.add_column("OTX Pulses")
    table.add_column("Risk Level")

    row = enrich_ip(args.ip)
    table.add_row(*row)
    console.print(table)
    exit()


# ---------------------------------------------------------------------------
# Mode: -f/--file  (a text file full of IPs)
# ---------------------------------------------------------------------------
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
table = Table(title="IOC Enrichment Results")
table.add_column("IP")
table.add_column("Reverse DNS")
table.add_column("In Blocklist")
table.add_column("VT Detection")
table.add_column("AbuseIPDB Score")
table.add_column("Shodan Info")
table.add_column("OTX Pulses")
table.add_column("Risk Level")

for ip in ips:
    row = enrich_ip(ip)
    table.add_row(*row)

console.print(table)
