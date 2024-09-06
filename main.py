from argparse import ArgumentParser, Namespace
from scapy.all import sr1, IP, ICMP
import ipaddress
import socket
import ssl
import json

# Function to perform ICMP ping sweep
def ping_sweep(ip_range):
    active_hosts = []
    unreachable_hosts = []
    
    try:
        for ip in ipaddress.IPv4Network(ip_range):
            print(f"Pinging {ip}...")
            response = sr1(IP(dst=str(ip))/ICMP(), timeout=1, verbose=False)
            
            if response is None:
                print(f"{ip} is unreachable.")
                unreachable_hosts.append(str(ip))
            else:
                print(f"{ip} is active.")
                active_hosts.append(str(ip))
                
    except ValueError as e:
        print(f"Error: {e}")
    
    return active_hosts, unreachable_hosts

# Function to perform TCP port scanning
def tcp_scan(ip, port_range):
    open_ports = []
    for port in port_range:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
    return open_ports

# Function to perform UDP port scanning
def udp_scan(ip, port_range):
    open_ports = []
    for port in port_range:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        try:
            sock.sendto(b'', (ip, port))
            sock.recvfrom(1024)
            open_ports.append(port)
        except socket.timeout:
            pass
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()
    return open_ports

# List of known vulnerable versions 
known_vulnerabilities = {
    80: {
        "Apache/2.2.8": "Apache 2.2.8 is known to have several vulnerabilities, including mod_proxy DoS.",
        "Apache/2.4.49": "Apache 2.4.49 is vulnerable to a path traversal attack (CVE-2021-41773).",
        "nginx/1.14.0": "nginx 1.14.0 is vulnerable to multiple issues, including buffer overflow (CVE-2019-20372).",
        "Microsoft-IIS/7.5": "Microsoft IIS 7.5 is vulnerable to remote code execution (CVE-2017-7269)."
    },
    443: {
        "OpenSSL/1.0.1": "OpenSSL 1.0.1 has Heartbleed vulnerability (CVE-2014-0160).",
        "OpenSSL/1.1.0": "OpenSSL 1.1.0 is vulnerable to padding oracle attacks (CVE-2019-1559).",
        "nginx/1.10.3": "nginx 1.10.3 has multiple vulnerabilities, including HTTP/2 frame flood (CVE-2018-16845).",
        "Apache/2.4.46": "Apache 2.4.46 is vulnerable to request splitting (CVE-2020-35452)."
    },
    21: {
        "ProFTPD 1.3.5": "ProFTPD 1.3.5 is vulnerable to mod_copy remote command execution (CVE-2015-3306).",
        "vsftpd 2.3.4": "vsftpd 2.3.4 contains a backdoor allowing remote attackers to gain a shell (CVE-2011-2523)."
    },
    22: {
        "OpenSSH 7.2p2": "OpenSSH 7.2p2 is vulnerable to a user enumeration attack (CVE-2016-6210).",
        "OpenSSH 8.0": "OpenSSH 8.0 has a vulnerability that allows bypassing authentication restrictions (CVE-2019-6111)."
    },
    3306: {
        "MySQL 5.1": "MySQL 5.1 is vulnerable to remote privilege escalation (CVE-2010-3833).",
        "MySQL 5.5": "MySQL 5.5 allows remote attackers to bypass authentication via a crafted authentication packet (CVE-2012-2122)."
    },
    25: {
        "Postfix 2.10": "Postfix 2.10 is vulnerable to command injection (CVE-2019-10149).",
        "Exim 4.89": "Exim 4.89 has a critical remote code execution vulnerability (CVE-2019-10149)."
    },
    143: {
        "Dovecot 2.2.10": "Dovecot 2.2.10 is vulnerable to multiple issues, including privilege escalation (CVE-2015-3420)."
    },
    53: {
        "BIND 9.9.5": "BIND 9.9.5 is vulnerable to denial of service via crafted queries (CVE-2016-2776)."
    },
    110: {
        "Dovecot 2.2.9": "Dovecot 2.2.9 has vulnerabilities in POP3/IMAP servers leading to DoS (CVE-2015-3420).",
        "qpopper 4.0.5": "qpopper 4.0.5 is vulnerable to buffer overflow (CVE-2010-1140)."
    }
}


# Function to check for known vulnerabilities
def check_vulnerabilities(banner, port):
    vulnerabilities = known_vulnerabilities.get(port, {})
    for version, description in vulnerabilities.items():
        if version in banner:
            return description
    return "No known vulnerabilities found"

# Function to perform basic OS fingerprinting
def os_fingerprinting(ip):
    ttl_values = {
        'Windows': (128, 129),  # Typical TTL values for Windows
        'Linux': (64,),  # Typical TTL values for Linux
        'Cisco': (255,),  # Typical TTL values for Cisco devices
        # Add more TTL values for other OSes
    }
    
    try:
        response = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=False)
        if response:
            ttl = response.ttl
            for os, ttl_range in ttl_values.items():
                if ttl in ttl_range:
                    return os
        return "Unknown OS"
    except Exception as e:
        print(f"Error performing OS fingerprinting for {ip} - {e}")
        return "Error"


# Function to grab banners from common services
def grab_banner(ip, port):
    service_banners = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)  # Increased timeout
            if port == 443:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    ssock.connect((ip, port))
                    # Sending a dummy request to get a banner for HTTPS
                    ssock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    banner = ssock.recv(1024).decode('utf-8', errors='ignore')
            else:
                sock.connect((ip, port))
                if port == 80:
                    sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                elif port == 22:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                elif port == 21:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                else:
                    banner = "No specific banner retrieval implemented for this port"
            
            service_banners[port] = banner.strip()
    except Exception as e:
        print(f"Error grabbing banner from {ip}:{port} - {e}")
        service_banners[port] = "Error"
    
    return service_banners


# CLI setup
parser = ArgumentParser()
parser.add_argument('--target', type=str, required=True, help="Target IP or IP range (e.g., 192.168.1.0/24)")
parser.add_argument('--ports', type=str, help="Comma-separated list of ports or ranges (e.g., 22,80,1000-2000)")
parser.add_argument('--protocol', choices=['tcp', 'udp'], default='tcp', help='Protocol to scan (tcp or udp)')
parser.add_argument('--output', choices=['text', 'json'], default='text', help='Output format')

args: Namespace = parser.parse_args()

# Perform the ping sweep
active, unreachable = ping_sweep(args.target)

# Initialize open_ports, all_banners, and vulnerabilities
open_ports = []
all_banners = []
vulnerabilities = []

# Only perform port scan if there are active hosts
if active:
    port_range = []
    if args.ports:
        try:
            ports = args.ports.split(',')
            for p in ports:
                if '-' in p:
                    start, end = map(int, p.split('-'))
                    port_range.extend(range(start, end + 1))
                else:
                    port_range.append(int(p))
        except ValueError:
            print("Error: Invalid port format. Please provide valid ports or ranges.")
            exit(1)
    else:
        # Use a default set of common ports if none are provided
        port_range = [21, 22, 23, 25, 80, 110, 143, 443]

    print("\nScan Results:")

    for ip in active:
        print(f"\nScanning {ip}...")
        
        if args.protocol == 'tcp':
            open_ports = tcp_scan(ip, port_range)
        elif args.protocol == 'udp':
            open_ports = udp_scan(ip, port_range)
        
        print(f"Open ports: {open_ports}")
        
        # Grabbing banners and checking for vulnerabilities
        for port in open_ports:
            banner = grab_banner(ip, port)
            all_banners.append(banner)
            vulnerability_info = check_vulnerabilities(banner, port)
            vulnerabilities.append({
                'ip': ip,
                'port': port,
                'banner': banner,
                'vulnerability_info': vulnerability_info
            })
            print(f"Banner for port {port}: {banner}")
            print(f"Vulnerability info: {vulnerability_info}")

        # Performing OS fingerprinting
        os_info = os_fingerprinting(ip)
        print(f"OS Fingerprinting: {os_info}")

else:
    print("No active hosts to scan.")

# Optional: Output to file in JSON or text format
if args.output == 'json':
    with open('scan_results.json', 'w') as file:
        json.dump({
            'active_hosts': active,
            'unreachable_hosts': unreachable,
            'open_ports': open_ports,
            'banners': all_banners,
            'vulnerabilities': vulnerabilities
        }, file)
        print("Results saved to scan_results.json")
else:
    with open('scan_results.txt', 'w') as file:
        file.write(f"Active hosts: {', '.join(active)}\n")
        file.write(f"Unreachable hosts: {', '.join(unreachable)}\n")
        file.write(f"Open ports: {open_ports}\n")
        file.write(f"Banners: {all_banners}\n")
        file.write(f"Vulnerabilities: {vulnerabilities}\n")
        print("Results saved to scan_results.txt")
