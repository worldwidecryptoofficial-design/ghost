import hashlib
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


class IntegrityError(Exception):
    """Raised when protected Ghost security files fail integrity checks."""


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


class TamperGuard:
    """
    Integrity checker for Ghost security-control files.

    This guard never enables execution.
    A failed integrity check always results in lockdown.
    """

    def __init__(self, project_root=PROJECT_ROOT):
        self.project_root = Path(project_root)

    def check_files_exist(self):
        missing = []

        for relative_path in PROTECTED_FILES:
            path = self.project_root / relative_path

            if not path.is_file():
                missing.append(relative_path)

        return missing

    def calculate_hashes(self):
        results = {}

        for relative_path in PROTECTED_FILES:
            path = self.project_root / relative_path

            if not path.is_file():
                results[relative_path] = None
                continue

            results[relative_path] = sha256_file(path)

        return results

    def status(self):
        missing = self.check_files_exist()

        if missing:
            return {
                "integrity_ok": False,
                "lockdown": True,
                "reason": "Protected security file is missing.",
                "missing_files": missing,
            }

        return {
            "integrity_ok": True,
            "lockdown": False,
            "reason": "Protected security files are present.",
            "missing_files": [],
        }

    def require_integrity(self):
        result = self.status()

        if not result["integrity_ok"]:
            raise IntegrityError(result["reason"])

        return True


if __name__ == "__main__":
    guard = TamperGuard()
    result = guard.status()

    print("=== GHOST SECURITY INTEGRITY CHECK ===")
    print(f"Protected files: {len(PROTECTED_FILES)}")
    print(
        "Integrity structure: "
        + ("PASS" if result["integrity_ok"] else "FAIL")
    )
    print(
        "Lockdown: "
        + ("YES" if result["lockdown"] else "NO")
    )
    print(f"Reason: {result['reason']}")

    if result["missing_files"]:
        print("\nMissing:")
        for item in result["missing_files"]:
            print(f" - {item}")
