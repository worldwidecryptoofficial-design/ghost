from pathlib import Path
import json

from security_core.offensive.release_verifier import (
    ProducerReleaseVerifier,
)


BASE_DIR = Path(__file__).resolve().parent
RELEASE_FILE = BASE_DIR / "producer_release.json"


class ReleasePolicyError(Exception):
    pass


class ProducerReleasePolicy:
    """
    Reads the producer-signed release and determines which
    high-risk capabilities the release explicitly authorizes.

    A verified signature alone is not sufficient.
    The capability must also be explicitly listed.
    """

    def __init__(self, release_file=RELEASE_FILE, verifier=None):
        self.release_file = Path(release_file)
        self.verifier = verifier or ProducerReleaseVerifier()

    def _load_release(self):
        if not self.release_file.exists():
            raise ReleasePolicyError("Producer release file is missing.")

        try:
            with self.release_file.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise ReleasePolicyError(
                f"Producer release is invalid: {exc}"
            )

    def verification_status(self):
        verified, reason = self.verifier.verify()

        return {
            "verified": verified,
            "reason": reason,
        }

    def released_capabilities(self):
        verified, reason = self.verifier.verify()

        if not verified:
            return []

        release = self._load_release()

        capabilities = release.get(
            "enabled_capabilities",
            []
        )

        if not isinstance(capabilities, list):
            raise ReleasePolicyError(
                "enabled_capabilities must be a list."
            )

        return sorted(
            {
                str(capability).strip()
                for capability in capabilities
                if str(capability).strip()
            }
        )

    def is_released(self, capability):
        if not capability or not capability.strip():
            return False

        return capability in self.released_capabilities()

    def status(self):
        verification = self.verification_status()

        capabilities = []

        if verification["verified"]:
            capabilities = self.released_capabilities()

        return {
            "producer_release_verified": verification["verified"],
            "verification": verification["reason"],
            "released_capabilities": capabilities,
        }
