import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
IDENTITY_FILE = BASE_DIR / "producer_identity.json"


class ProducerIdentityError(Exception):
    """Raised when producer identity data is invalid."""
    pass


class ProducerIdentity:
    """
    Identifies the producer associated with Ghost's release system.

    Email addresses identify the producer.
    Cryptographic signatures remain the actual release authority.
    """

    def __init__(self, identity_file=IDENTITY_FILE):
        self.identity_file = Path(identity_file)

    def load(self):
        if not self.identity_file.exists():
            raise ProducerIdentityError(
                "Producer identity file is missing."
            )

        try:
            with self.identity_file.open(
                "r",
                encoding="utf-8"
            ) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise ProducerIdentityError(
                f"Producer identity is invalid: {exc}"
            )

        required = {
            "producer_id",
            "public_key_id",
            "role",
            "status",
        }

        missing = required - set(data)

        if missing:
            raise ProducerIdentityError(
                "Missing identity fields: "
                + ", ".join(sorted(missing))
            )

        if data["role"] != "producer":
            raise ProducerIdentityError(
                "Identity is not marked as producer."
            )

        if data["status"] != "active":
            raise ProducerIdentityError(
                "Producer identity is not active."
            )

        return data

    def status(self):
        identity = self.load()

        return {
            "producer_id": identity["producer_id"],
            "public_key_id": identity["public_key_id"],
            "role": identity["role"],
            "status": identity["status"],
        }
