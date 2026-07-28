\# IOC Enricher



A Python command-line tool that enriches IP addresses and file hashes with real threat intelligence data from VirusTotal, AbuseIPDB, Shodan, and AlienVault OTX, and calculates a combined risk score.



\## Usage



\*\*Check a list of IPs from a file:\*\*

python ioc\_enricher.py -f <filename>



Example:

python ioc\_enricher.py -f test\_ips.txt



\*\*Check a single file hash:\*\*

python ioc\_enricher.py --hash <hash>



Example:

python ioc\_enricher.py --hash 44d88612fea8a8f36de82e1278abb02f



\## Input Format (IP mode)

A text file with one IP address per line.



\## Output

For IPs: a table showing Reverse DNS, blocklist status, VirusTotal detection count, AbuseIPDB abuse confidence score, Shodan open ports/ISP, AlienVault OTX pulse count, and a combined Risk Level (Low/Medium/High).



For hashes: a table showing VirusTotal's Malicious/Suspicious/Harmless engine counts.



\## Combined Risk Score Logic

Risk is rated HIGH if any of the following are true:

\- IP is on the internal blocklist

\- VirusTotal shows 1+ malicious detections

\- AbuseIPDB confidence score is above 50

\- AlienVault OTX pulse count is above 5



Otherwise, MEDIUM if no reverse DNS record exists, and LOW if the IP appears clean.



\## Edge Cases Handled

\- Invalid IP addresses (marked "Invalid IP", skipped safely)

\- DNS lookup timeouts (3-second limit)

\- Missing input file (clear error message, no crash)

\- API rate limiting (HTTP 429) handled with exponential backoff on VirusTotal and AbuseIPDB requests

\- Malformed/unexpected API responses (e.g., AlienVault OTX) handled gracefully, defaulting to safe values instead of crashing



\## Known Limitations

\- Shodan's free "oss" tier has 0 query credits for on-demand scans, but host lookups for well-known/pre-indexed IPs (e.g., major DNS providers) still return data successfully in testing. Lesser-known IPs may return an error under this tier.

\- API keys are stored as plain variables in the script for this exercise; in a production tool, these should be loaded from environment variables or a separate config file, not hardcoded.



\## Requirements

pip install requests rich shodan

