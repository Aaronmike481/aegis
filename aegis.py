import socket
import json
import sys

WORDS = ["www", "mail", "api", "dev", "admin", "test", "blog", "shop", "app"]
PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 27017]

def scan_domains(domain):
    found = []
    for word in WORDS:
        subdomain = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            found.append({"name": subdomain, "ip": ip})
        except socket.gaierror:
            pass
    return found

def is_port_open(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0

def scan_ports(host, ports):
    open_ports = []
    for port in ports:
        if is_port_open(host, port):
            open_ports.append({"port": port, "state": "open"})
    return open_ports

def aegis(domain):
    subdomains = scan_domains(domain)
    results = []
    for sub in subdomains:
        open_ports = scan_ports(sub["name"], PORTS)
        results.append({
            "host": sub["name"],
            "ip": sub["ip"],
            "open_ports": open_ports,
        })
    return {
        "target": domain,
        "subdomains_found": len(subdomains),
        "results": results,
    }

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    output = aegis(domain)
    print(json.dumps(output, indent=2))