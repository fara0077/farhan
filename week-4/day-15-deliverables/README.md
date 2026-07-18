# IP Checker

A Python script that checks a list of IP addresses against a hardcoded blocklist and performs reverse DNS lookups.

## Usage

python3 ip_checker.py -f <filename>

Example:
python3 ip_checker.py -f test_ips.txt

## Input Format
A text file with one IP address per line.

## Output
A formatted table showing: IP, Reverse DNS hostname, whether it's in the blocklist, and a Risk Level (Low/Medium/High).

## Edge Cases Handled
- Invalid IP addresses (marked as "Invalid IP")
- DNS lookup timeouts (marked as "DNS Timeout", 3-second limit)
- Missing input file (clear error message, no crash)
