import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security_core.audit.audit_logger import SecurityAuditLogger


BASE_DIR = PROJECT_ROOT
AUDIT_DIR = BASE_DIR / "security_core" / "audit" / "records"
MIGRATION_FILE = AUDIT_DIR / "chain_migration.json"


def inspect_legacy_records():
    legacy = []

    for path in sorted(AUDIT_DIR.glob("*.json")):
        if path.name == MIGRATION_FILE.name:
            continue

        try:
            data = json.loads(
                path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            continue

        if "record_hash" not in data:
            legacy.append(path.name)

    return legacy


def create_boundary():
    legacy = inspect_legacy_records()

    if MIGRATION_FILE.exists():
        print("CHAIN_MIGRATION: ALREADY_EXISTS")
        print(MIGRATION_FILE)
        return 0

    boundary = {
        "version": 1,
        "type": "audit_chain_boundary",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "legacy_record_count": len(legacy),
        "legacy_records_preserved": True,
        "legacy_records_modified": False,
        "message": (
            "Records created before hash chaining are preserved as "
            "legacy audit history. Hash-chain verification begins "
            "with records created after this boundary."
        ),
    }

    MIGRATION_FILE.write_text(
        json.dumps(boundary, indent=2) + "\n",
        encoding="utf-8",
    )

    print("=== GHOST AUDIT CHAIN BOUNDARY ===")
    print("Status: CREATED")
    print(f"Legacy records: {len(legacy)}")
    print("Legacy records modified: NO")
    print(f"Boundary: {MIGRATION_FILE}")

    return 0


if __name__ == "__main__":
    raise SystemExit(create_boundary())
