import json
from pathlib import Path


ASSET_FILE = Path(__file__).resolve().parent / "authorized_assets.json"


class AuthorizationError(Exception):
    """Raised when an operation is not authorized."""
    pass


class AuthorizationEngine:
    def __init__(self, asset_file=ASSET_FILE):
        self.asset_file = Path(asset_file)

    def _load(self):
        if not self.asset_file.exists():
            raise AuthorizationError(
                "Authorization database does not exist."
            )

        try:
            with self.asset_file.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise AuthorizationError(
                f"Authorization database is invalid: {exc}"
            )

    def assets(self):
        data = self._load()
        return data.get("assets", [])

    def is_authorized(self, asset_id, operation):
        data = self._load()

        policy = data.get("policy", {})

        if policy.get("default_action", "deny") != "deny":
            return False

        if not policy.get("require_explicit_authorization", True):
            return False

        for asset in data.get("assets", []):
            if asset.get("id") != asset_id:
                continue

            if asset.get("enabled") is not True:
                return False

            allowed_operations = asset.get("operations", [])

            return (
                operation in allowed_operations
                or "*" in allowed_operations
            )

        return False

    def require_authorization(self, asset_id, operation):
        if not self.is_authorized(asset_id, operation):
            raise AuthorizationError(
                f"Operation '{operation}' is not authorized "
                f"for asset '{asset_id}'."
            )

        return True
