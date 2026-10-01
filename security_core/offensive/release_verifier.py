import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


BASE_DIR = Path(__file__).resolve().parent

RELEASE_FILE = BASE_DIR / "producer_release.json"
PUBLIC_KEY_FILE = BASE_DIR / "producer_public_key.pem"
IDENTITY_FILE = BASE_DIR / "producer_identity.json"


class ReleaseVerificationError(Exception):
    pass


class ProducerReleaseVerifier:
    """
    Verifies a producer-signed Ghost release.

    The producer emails are identity metadata.
    The Ed25519 signature is the actual cryptographic proof.

    The private signing key is never stored in Ghost.
    """

    def __init__(
        self,
        release_file=RELEASE_FILE,
        public_key_file=PUBLIC_KEY_FILE,
        identity_file=IDENTITY_FILE,
    ):
        self.release_file = Path(release_file)
        self.public_key_file = Path(public_key_file)
        self.identity_file = Path(identity_file)

    def _load_json(self, path, description):
        if not path.exists():
            raise ReleaseVerificationError(
                f"{description} is missing."
            )

        try:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise ReleaseVerificationError(
                f"{description} is invalid: {exc}"
            )

    def verify(self):
        try:
            release = self._load_json(
                self.release_file,
                "Producer release",
            )

            identity = self._load_json(
                self.identity_file,
                "Producer identity",
            )

            if identity.get("role") != "producer":
                return False, "Configured identity is not a producer."

            if identity.get("status") != "active":
                return False, "Producer identity is not active."

            producer_id = identity.get("producer_id")

            if not producer_id:
                return False, "Producer ID is missing."

            release_producer = release.get("producer_id")

            if release_producer != producer_id:
                return False, "Release producer ID does not match."

            signature_b64 = release.get("producer_signature")

            if not signature_b64:
                return False, "Producer signature is missing."

            payload = release.get("signed_payload")

            if not isinstance(payload, dict):
                return False, "Signed payload is missing."

            payload_producer = payload.get("producer_id")

            if payload_producer != producer_id:
                return False, "Signed producer ID does not match."

            signature = base64.b64decode(
                signature_b64,
                validate=True,
            )

            public_key = serialization.load_pem_public_key(
                self.public_key_file.read_bytes()
            )

            if not isinstance(
                public_key,
                ed25519.Ed25519PublicKey,
            ):
                return False, "Unsupported producer public-key type."

            canonical_payload = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")

            public_key.verify(
                signature,
                canonical_payload,
            )

            return True, "Producer signature verified."

        except (ValueError, TypeError):
            return False, "Invalid release signature encoding."

        except Exception:
            return False, "Producer signature verification failed."
