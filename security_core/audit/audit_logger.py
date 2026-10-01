import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
AUDIT_DIR = BASE_DIR / "security_core" / "audit" / "records"
MIGRATION_FILE = AUDIT_DIR / "chain_migration.json"
GENESIS_HASH = "0" * 64


class SecurityAuditLogger:
    """
    Tamper-evident security audit logger.

    Records created before hash chaining are treated as legacy history.
    Records after the chain boundary are hash-linked.
    """

    def __init__(self, audit_dir=AUDIT_DIR):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)

    def _canonical_json(self, data):
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def _hash_record(self, record):
        payload = self._canonical_json(record).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _record_files(self):
        return sorted(
            path
            for path in self.audit_dir.glob("*.json")
            if path.name != MIGRATION_FILE.name
        )

    def _hash_chained_records(self):
        return [
            path
            for path in self._record_files()
            if self._is_chained_file(path)
        ]

    def _is_chained_file(self, path):
        try:
            data = json.loads(
                path.read_text(encoding="utf-8")
            )
            return (
                "record_hash" in data
                and "previous_hash" in data
            )
        except (OSError, json.JSONDecodeError):
            return False

    def _last_chained_record(self):
        records = self._hash_chained_records()

        if not records:
            return None

        try:
            return json.loads(
                records[-1].read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            return None

    def record(
        self,
        event,
        status,
        capability=None,
        asset_id=None,
        details=None,
    ):
        previous = self._last_chained_record()

        previous_hash = (
            previous.get("record_hash", GENESIS_HASH)
            if previous
            else GENESIS_HASH
        )

        entry = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "status": status,
            "capability": capability,
            "asset_id": asset_id,
            "details": details or {},
            "previous_hash": previous_hash,
        }

        entry["record_hash"] = self._hash_record(entry)

        filename = (
            f"{entry['timestamp'].replace(':', '-')}"
            f"-{entry['event_id']}.json"
        )

        path = self.audit_dir / filename

        path.write_text(
            json.dumps(entry, indent=2) + "\n",
            encoding="utf-8",
        )

        return entry

    def list_events(self):
        events = []

        for path in self._record_files():
            try:
                events.append(
                    json.loads(
                        path.read_text(encoding="utf-8")
                    )
                )
            except (OSError, json.JSONDecodeError):
                continue

        return events

    def verify_chain(self):
        """
        Verify only the cryptographically chained audit records.

        Legacy records are preserved and reported separately.
        """

        all_records = self._record_files()

        legacy_count = 0
        chained = []

        for path in all_records:
            try:
                record = json.loads(
                    path.read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError):
                continue

            if (
                "record_hash" not in record
                or "previous_hash" not in record
            ):
                legacy_count += 1
            else:
                chained.append(record)

        if not chained:
            return True, (
                "No hash-chained records yet. "
                f"Legacy records preserved: {legacy_count}."
            )

        expected_previous = GENESIS_HASH

        for index, record in enumerate(chained):
            stored_hash = record.get("record_hash")

            if not stored_hash:
                return False, (
                    f"Chained record {index} is missing record_hash."
                )

            actual_previous = record.get("previous_hash")

            if actual_previous != expected_previous:
                return False, (
                    f"Broken audit chain at chained record {index}."
                )

            data_without_hash = dict(record)
            data_without_hash.pop("record_hash", None)

            calculated_hash = self._hash_record(
                data_without_hash
            )

            if calculated_hash != stored_hash:
                return False, (
                    f"Chained record {index} failed hash verification."
                )

            expected_previous = stored_hash

        return True, (
            "Audit hash chain verified. "
            f"Legacy records preserved: {legacy_count}. "
            f"Chained records verified: {len(chained)}."
        )

    def verify(self):
        return self.verify_chain()


if __name__ == "__main__":
    logger = SecurityAuditLogger()

    entry = logger.record(
        event="audit_logger_test",
        status="PASS",
        details={
            "message": "Security audit logger operational."
        },
    )

    verified, reason = logger.verify_chain()

    print("=== GHOST SECURITY AUDIT LOGGER ===")
    print("Record Status: PASS")
    print(f"Event ID: {entry['event_id']}")
    print(f"Record Hash: {entry['record_hash']}")
    print(f"Previous Hash: {entry['previous_hash']}")
    print(f"Records: {len(logger.list_events())}")
    print(
        "Chain Verification: "
        + ("PASS" if verified else "FAIL")
    )
    print(f"Verification: {reason}")
