CAPABILITIES = {
    "arp_dos": "UNLOCKED",
    "arp_spoof": "UNLOCKED",
    "dhcp_dos": "UNLOCKED",
    "dns_spoof": "UNLOCKED",
    "email_bomber": "UNLOCKED",
    "mac_spoof": "UNLOCKED",
    "mitm": "UNLOCKED",
    "network_kill": "UNLOCKED",
    "rar_cracker": "UNLOCKED",
    "web_killer": "UNLOCKED",
    "wifi_jammer": "UNLOCKED",
    "zip_cracker": "UNLOCKED",
}

for name, status in CAPABILITIES.items():
    print("[{}] {}".format(status, name))

print("All-unlocked state parsed successfully.")
