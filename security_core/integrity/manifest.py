import hashlib
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

PROTECTED_FILES = [
    "security_core/offensive/capability_lock_registry.py",
    "security_core/offensive/execution_controller.py",
    "security_core/offensive/release_policy.py",
    "security_core/offensive/release_verifier.py",
    "security_core/offensive/producer_identity.py",
    "security_core/offensive/producer_identity.json",
    "security_core/offensive/producer_release.json",
    "security_core/offensive/producer_public_key.pem",
    "security_core/inventory/authorization.py",
    "security_core/inventory/authorized_assets.json",
    "security_core/audit/audit_logger.py",
    "security_core/audit/chain_migration.py",
]

MANIFEST_FILE = (
    PROJECT_ROOT
    / "security_core"
    / "integrity"
    / "integrity_manifest.json"
)


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def build_manifest():
    files = {}

    for relative_path in PROTECTED_FILES:
        path = PROJECT_ROOT / relative_path

        if not path.is_file():
            raise FileNotFoundError(
                f"Protected file is missing: {relative_path}"
            )

        files[relative_path] = sha256_file(path)

    return {
        "version": 1,
        "algorithm": "SHA-256",
        "files": dict(sorted(files.items())),
    }


def write_manifest():
    manifest = build_manifest()

    MANIFEST_FILE.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    return manifest


def load_manifest():
    if not MANIFEST_FILE.is_file():
        raise FileNotFoundError(
            "Integrity manifest is missing."
        )

    return json.loads(
        MANIFEST_FILE.read_text(encoding="utf-8")
    )


def verify_manifest():
    manifest = load_manifest()

    if manifest.get("algorithm") != "SHA-256":
        return False, "Unsupported integrity algorithm."

    expected = manifest.get("files")

    if not isinstance(expected, dict):
        return False, "Integrity manifest is invalid."

    for relative_path, expected_hash in expected.items():
        path = PROJECT_ROOT / relative_path

        if not path.is_file():
            return False, (
                f"Protected file is missing: {relative_path}"
            )

        actual_hash = sha256_file(path)

        if actual_hash != expected_hash:
            return False, (
                f"Integrity mismatch: {relative_path}"
            )

    return True, "Integrity manifest verified."


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2 and sys.argv[1] == "--create":
        write_manifest()
        print("Integrity manifest created.")
        print(f"Protected files: {len(PROTECTED_FILES)}")
        sys.exit(0)

    ok, reason = verify_manifest()

    print("=== GHOST INTEGRITY MANIFEST ===")
    print(f"Protected files: {len(PROTECTED_FILES)}")
    print(f"Verification: {'PASS' if ok else 'FAIL'}")
    print(f"Reason: {reason}")

    sys.exit(0 if ok else 1)
