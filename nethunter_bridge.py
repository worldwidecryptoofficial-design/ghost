import os
import shutil
import subprocess

IS_KALI = (
    os.path.exists("/etc/kali-release")
    or (
        os.path.exists("/etc/os-release")
        and "ID=kali" in open("/etc/os-release", "r", encoding="utf-8").read()
    )
)

NH = None if IS_KALI else (shutil.which("nethunter") or shutil.which("nh"))

TOOL_EXECUTABLES = {
    "nmap": ["nmap"],
    "masscan": ["masscan"],
    "sqlmap": ["sqlmap"],
    "hydra": ["hydra"],
    "tcpdump": ["tcpdump"],
    "aircrack-ng": ["aircrack-ng", "aircrack"],
    "hashcat": ["hashcat"],
    "john": ["john", "john-the-ripper"],
    "metasploit": ["msfconsole", "msfvenom"],
    "ss": ["ss"],
    "ip": ["ip"],
    "ping": ["ping"],
    "traceroute": ["traceroute"],
    "dig": ["dig"],
    "nslookup": ["nslookup"],
    "whois": ["whois"],
    "openssl": ["openssl"],
    "socat": ["socat"],
    "netcat": ["nc"],
    "tshark": ["tshark"],
    "nikto": ["nikto"],
    "gobuster": ["gobuster"],
    "ffuf": ["ffuf"],
    "feroxbuster": ["feroxbuster"],
    "whatweb": ["whatweb"],
    "amass": ["amass"],
    "dnsrecon": ["dnsrecon"],
    "curl": ["curl"],
    "wget": ["wget"],
    "git": ["git"],
    "python3": ["python3"],
    "ruby": ["ruby"],
    "golang": ["go"],
    "unzip": ["unzip"],
}


def nethunter_available():
    return IS_KALI or NH is not None


def nh_exec(args, timeout=30):
    try:
        command = list(args) if IS_KALI else [NH] + list(args)

        if not IS_KALI and not NH:
            return False, "NetHunter executable not found"

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        output = ((result.stdout or "") + (result.stderr or "")).strip()
        return result.returncode == 0, output

    except subprocess.TimeoutExpired:
        return False, "Command timed out"

    except Exception as exc:
        return False, str(exc)


def find_tool(executables):
    for executable in executables:
        if IS_KALI:
            path = shutil.which(executable)
            if path:
                return path

        elif NH:
            ok, output = nh_exec(["which", executable])

            if ok and output:
                return output.splitlines()[0].strip()

    return None


def tool_inventory():
    results = {}

    for name, executables in TOOL_EXECUTABLES.items():
        path = find_tool(executables)

        results[name] = {
            "installed": path is not None,
            "path": path,
        }

    return results


def kali_tool_status():
    return tool_status()


def tool_status():
    inventory = tool_inventory()

    installed = [
        name for name, data in inventory.items()
        if data["installed"]
    ]

    missing = [
        name for name, data in inventory.items()
        if not data["installed"]
    ]

    return {
        "total": len(inventory),
        "installed": len(installed),
        "missing": len(missing),
        "installed_tools": installed,
        "missing_tools": missing,
        "inventory": inventory,
    }


def kali_status():
    ok, output = nh_exec(["cat", "/etc/os-release"])

    if not ok:
        return False, output or "Kali did not respond"

    return True, "KALI_OK"


def kali_identity():
    return nh_exec(["id"])


def kali_python():
    return nh_exec(["python3", "--version"])


if __name__ == "__main__":
    status = tool_status()

    print("=== GHOST KALI TOOL INVENTORY ===")
    print(f"Installed: {status['installed']}/{status['total']}")

    for name, data in status["inventory"].items():
        if data["installed"]:
            print(f"✓ {name:<15} {data['path']}")
        else:
            print(f"✗ {name:<15} NOT FOUND")


def kali_tool_status():
    """Compatibility wrapper used by Ghost."""
    return tool_status()


def run_kali_safe(command):
    """
    Run only Ghost's predefined diagnostic/version commands.
    This does not provide unrestricted shell execution.
    """
    if not command or not command.strip():
        return False, "No command supplied"

    parts = command.strip().split()
    tool = parts[0]

    diagnostic_commands = {
        "nmap": ["--version"],
        "masscan": ["--version"],
        "sqlmap": ["--version"],
        "hydra": ["-h"],
        "tcpdump": ["--version"],
        "curl": ["--version"],
        "wget": ["--version"],
        "git": ["--version"],
        "python3": ["--version"],
        "ruby": ["--version"],
        "go": ["version"],
        "john": ["--version"],
        "hashcat": ["--version"],
        "aircrack-ng": ["--version"],
        "unzip": ["--version"],
        "msfconsole": ["--version"],
        "msfvenom": ["--version"],
    }

    if tool not in diagnostic_commands:
        return False, "Tool is not available through the diagnostic interface"

    expected = [tool] + diagnostic_commands[tool]

    if parts != expected:
        return False, "Only the predefined diagnostic command is allowed"

    return nh_exec(parts)
