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

SAFE_TOOLS = {
    "nmap": ["--version"],
    "masscan": ["--version"],
    "hydra": ["-h"],
    "sqlmap": ["--version"],
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
            timeout=timeout
        )

        output = (
            (result.stdout or "") +
            (result.stderr or "")
        ).strip()

        return result.returncode == 0, output

    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as exc:
        return False, str(exc)

def kali_status():
    ok, output = nh_exec(["cat", "/etc/os-release"])

    if not ok:
        return False, output or "Kali did not respond"

    return True, "KALI_OK"


def kali_identity():
    return nh_exec(["id"])

def kali_python():
    return nh_exec(["python3", "--version"])

def kali_tool_status(tool=None):
    tools = [
        "nmap",
        "masscan",
        "sqlmap",
        "hydra",
        "tcpdump",
        "curl",
        "wget",
        "git",
        "python3",
        "ruby",
        "go",
        "john",
        "hashcat",
        "aircrack-ng",
        "unzip",
        "msfconsole",
        "msfvenom",
    ]

    def check(name):
        ok, output = nh_exec(
            ["which", name],
            timeout=30
        )

        return {
            "installed": ok and bool(output),
            "connected": ok,
            "output": output
        }

    if tool:
        return check(tool)

    return {name: check(name) for name in tools}

def run_kali_safe(command):
    if not command or not command.strip():
        return False, "No command supplied"

    parts = command.strip().split()
    tool = parts[0]

    if tool not in SAFE_TOOLS:
        return False, "Only approved diagnostic/version commands are available"

    expected = SAFE_TOOLS[tool]

    if parts != [tool] + expected:
        return False, "Only the predefined diagnostic command is allowed"

    return nh_exec(parts)
