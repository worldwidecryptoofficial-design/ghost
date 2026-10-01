MODULE_POLICY = {
    # Defensive
    "apache_users": "UNLOCKED",
    "arp_monitor": "UNLOCKED",
    "cloudflare_resolver": "UNLOCKED",
    "hostname_resolver": "UNLOCKED",
    "pma_scanner": "UNLOCKED",
    "port_scanner": "UNLOCKED",
    "proxy_detector": "UNLOCKED",
    "wordlist_gen": "UNLOCKED",

    # Offensive — intentionally unlocked
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

    # Requires review
    "bluetooth_pod.corrupt": "REVIEW",
    "dir_scanner": "REVIEW",
}

def get_status(name):
    return MODULE_POLICY.get(name.removesuffix(".py"), "REVIEW")

if __name__ == "__main__":
    for name in sorted(MODULE_POLICY):
        print("[{}] {}".format(MODULE_POLICY[name], name))

    print("Total:", len(MODULE_POLICY))
