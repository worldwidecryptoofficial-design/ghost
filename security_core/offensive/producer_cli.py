#!/usr/bin/env python3

import argparse
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
IDENTITY_FILE = BASE / "producer_identity.json"
RELEASE_FILE = BASE / "producer_release.json"


def load_json(path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def status():
    identity = load_json(IDENTITY_FILE)
    release = load_json(RELEASE_FILE)

    print()
    print("╔══════════════════════════════════════════════╗")
    print("║             GHOST PRODUCER CONTROL           ║")
    print("╠══════════════════════════════════════════════╣")
    print(f"║ Producer ID:       {identity.get('producer_id', 'UNKNOWN'):<20} ║")
    print(f"║ Producer Status:   {identity.get('status', 'UNKNOWN'):<20} ║")
    print(f"║ Release Status:    {release.get('status', 'UNKNOWN'):<20} ║")
    print(f"║ Release Version:   {release.get('release_version', 0):<20} ║")
    print(f"║ Capabilities:      {len(release.get('enabled_capabilities', [])):<20} ║")
    print("║ High-Risk Backend: LOCKED               ║")
    print("╚══════════════════════════════════════════════╝")
    print()


def assets():
    asset_file = BASE.parent.parent / "inventory" / "authorized_assets.json"

    if not asset_file.exists():
        print("No authorization database found.")
        return

    data = load_json(asset_file)
    registered = data.get("assets", [])

    print("\n=== PRODUCER AUTHORIZED ASSETS ===")

    if not registered:
        print("No assets registered.")
        return

    for asset in registered:
        print(
            f"- {asset.get('id', 'UNKNOWN')} | "
            f"enabled={asset.get('enabled', False)} | "
            f"operations={asset.get('operations', [])}"
        )


def audit():
    print("\n=== PRODUCER AUDIT ===")
    print("Audit records are managed by Ghost's tamper-evident audit subsystem.")
    print("Use the security audit tools to verify the complete chain.")


def lockdown():
    print("\n=== PRODUCER LOCKDOWN ===")
    print("Emergency lockdown remains enforced by Ghost's safety subsystem.")
    print("No execution capability is unlocked by this command.")


def main():
    parser = argparse.ArgumentParser(
        prog="producer",
        description="Ghost Producer Control"
    )

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status")
    sub.add_parser("assets")
    sub.add_parser("audit")
    sub.add_parser("lockdown")

    args = parser.parse_args()

    if args.command in (None, "status"):
        status()
    elif args.command == "assets":
        assets()
    elif args.command == "audit":
        audit()
    elif args.command == "lockdown":
        lockdown()


if __name__ == "__main__":
    main()
