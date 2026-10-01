from dataclasses import dataclass


@dataclass(frozen=True)
class HakkuModule:
    name: str
    category: str
    status: str
    description: str


MODULES = [
    HakkuModule(
        "apache_users", "web", "available",
        "Apache user enumeration/assessment."
    ),
    HakkuModule(
        "arp_dos", "network", "restricted",
        "ARP-based disruption module."
    ),
    HakkuModule(
        "arp_monitor", "network", "available",
        "Monitor ARP activity."
    ),
    HakkuModule(
        "arp_spoof", "network", "restricted",
        "ARP spoofing module."
    ),
    HakkuModule(
        "bluetooth_pod", "wireless", "restricted",
        "Bluetooth disruption/attack module."
    ),
    HakkuModule(
        "cloudflare_resolver", "web", "available",
        "Cloudflare-related DNS resolution utility."
    ),
    HakkuModule(
        "dhcp_dos", "network", "restricted",
        "DHCP disruption module."
    ),
    HakkuModule(
        "dir_scanner", "web", "available",
        "Web directory discovery."
    ),
    HakkuModule(
        "dns_spoof", "network", "restricted",
        "DNS spoofing module."
    ),
    HakkuModule(
        "email_bomber", "web", "restricted",
        "Mass-email/disruption module."
    ),
    HakkuModule(
        "hostname_resolver", "recon", "available",
        "Resolve hostnames."
    ),
    HakkuModule(
        "mac_spoof", "network", "restricted",
        "MAC-address spoofing module."
    ),
    HakkuModule(
        "mitm", "network", "restricted",
        "Man-in-the-middle module."
    ),
    HakkuModule(
        "network_kill", "network", "restricted",
        "Network communication disruption module."
    ),
    HakkuModule(
        "pma_scanner", "web", "available",
        "phpMyAdmin discovery/assessment."
    ),
    HakkuModule(
        "port_scanner", "network", "available",
        "Port discovery for authorized targets."
    ),
    HakkuModule(
        "proxy_scout", "network", "available",
        "Proxy discovery/assessment."
    ),
    HakkuModule(
        "whois", "recon", "available",
        "WHOIS information lookup."
    ),
    HakkuModule(
        "web_killer", "web", "restricted",
        "Web-service disruption module."
    ),
    HakkuModule(
        "web_scout", "web", "available",
        "Web reconnaissance."
    ),
    HakkuModule(
        "wifi_jammer", "wireless", "restricted",
        "Wireless interference/disruption module."
    ),
    HakkuModule(
        "zip_cracker", "files", "restricted",
        "ZIP password-cracking module."
    ),
    HakkuModule(
        "rar_cracker", "files", "restricted",
        "RAR password-cracking module."
    ),
    HakkuModule(
        "wordlist_gen", "generator", "available",
        "Generate wordlists for authorized security testing."
    ),
]


def list_modules():
    return MODULES


def get_module(name):
    for module in MODULES:
        if module.name == name:
            return module
    raise KeyError(f"Unknown module: {name}")
