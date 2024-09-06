# Network-Enumeration-and-Scanning-Tool
This command-line tool allows you to perform basic network scanning and enumeration tasks, including:

1. **ICMP Ping Sweep**: Identify active and unreachable hosts in a specified IP range.
2. **TCP/UDP Port Scanning**: Scan a range of ports on active hosts to identify open ones.
3. **Banner Grabbing**: Retrieve banners from open ports for service identification.
4. **Vulnerability Checking**: Match retrieved banners with known vulnerabilities.
5. **OS Fingerprinting**: Estimate the target's operating system based on TTL values.

## Features

- ICMP-based ping sweep for host discovery.
- TCP/UDP port scanning.
- Banner grabbing for service identification.
- Checking for known vulnerabilities based on retrieved banners.
- Basic OS fingerprinting.
- Output results in text or JSON format.

## Installation

To install the dependencies, run:

```bash
pip install scapy argparse
```

## Usage

Run the script with the following options:

```bash
python scanner.py --target <target_ip_or_range> [--ports <port_list_or_range>] [--protocol tcp/udp] [--output text/json]
```

### Parameters

- `--target`: Target IP or IP range (e.g., `192.168.1.0/24` or `192.168.1.5`).
- `--ports`: Comma-separated list of ports or port ranges to scan (e.g., `22,80,1000-2000`). Defaults to a set of common ports.
- `--protocol`: Protocol to use for port scanning (`tcp` or `udp`). Defaults to `tcp`.
- `--output`: Format of the output (`text` or `json`). Defaults to `text`.

### Example

```bash
python scanner.py --target 192.168.1.0/24 --ports 22,80,443 --protocol tcp --output json
```

This command will:

1. Perform a ping sweep of the network range `192.168.1.0/24`.
2. Scan ports 22, 80, and 443 using TCP on all active hosts.
3. Grab banners from open ports and check for known vulnerabilities.
4. Save the results to a JSON file (`scan_results.json`).

### Output

Results will be saved in either `scan_results.txt` (for text) or `scan_results.json` (for JSON) depending on the chosen format.

## Functionality Overview

- **Ping Sweep**: Uses ICMP to identify which hosts are reachable within the specified range.
- **Port Scanning**: Performs TCP/UDP scans on specified ports to check their status (open/closed).
- **Banner Grabbing**: Connects to common services (HTTP, HTTPS, SSH, FTP, etc.) to retrieve service banners for identification.
- **Vulnerability Checking**: Compares service banners with a list of known vulnerabilities and reports any matches.
- **OS Fingerprinting**: Provides a best-effort guess of the target's operating system based on TTL values in ICMP responses.

## Known Vulnerabilities

The tool includes a built-in database of known vulnerabilities for popular services and software versions. The database currently supports vulnerabilities for the following services:

- Apache, nginx, Microsoft IIS (HTTP/HTTPS)
- OpenSSL (HTTPS)
- MySQL (Database)
- OpenSSH (SSH)
- ProFTPD, vsftpd (FTP)
- Postfix, Exim (SMTP)
- Dovecot (POP3/IMAP)
- BIND (DNS)

## Notes

- Make sure you have appropriate permission to scan the target network, as unauthorized network scanning may violate legal regulations or security policies.
- This tool is designed for educational and ethical purposes. Please use it responsibly. 
