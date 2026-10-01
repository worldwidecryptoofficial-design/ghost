import json
from pathlib import Path


ASSET_FILE = Path(__file__).resolve().parent / "authorized_assets.json"


class AssetManagerError(Exception):
    """Raised when an asset-management operation fails."""
    pass


ALLOWED_OPERATIONS = {
    "defensive_inventory",
    "vulnerability_assessment",
    "authorized_recon",
    "configuration_audit",
    "security_validation",
    "evidence_collection",
}


class AssetManager:
    def __init__(self, asset_file=ASSET_FILE):
        self.asset_file = Path(asset_file)

    def _load(self):
        if not self.asset_file.exists():
            raise AssetManagerError(
                "Authorization database does not exist."
            )

        try:
            with self.asset_file.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise AssetManagerError(
                f"Authorization database is invalid: {exc}"
            )

    def _save(self, data):
        self.asset_file.parent.mkdir(parents=True, exist_ok=True)

        with self.asset_file.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")

    def list_assets(self):
        data = self._load()
        return data.get("assets", [])

    def register(
        self,
        asset_id,
        name,
        asset_type,
        operations,
        enabled=True,
    ):
        if not asset_id.strip():
            raise AssetManagerError("Asset ID cannot be empty.")

        if not name.strip():
            raise AssetManagerError("Asset name cannot be empty.")

        if not asset_type.strip():
            raise AssetManagerError("Asset type cannot be empty.")

        if not operations:
            raise AssetManagerError(
                "At least one explicit operation is required."
            )

        invalid = set(operations) - ALLOWED_OPERATIONS

        if invalid:
            raise AssetManagerError(
                "Unsupported operations: "
                + ", ".join(sorted(invalid))
            )

        data = self._load()
        assets = data.setdefault("assets", [])

        for asset in assets:
            if asset.get("id") == asset_id:
                raise AssetManagerError(
                    f"Asset '{asset_id}' already exists."
                )

        asset = {
            "id": asset_id,
            "name": name,
            "type": asset_type,
            "enabled": bool(enabled),
            "operations": sorted(set(operations)),
        }

        assets.append(asset)
        self._save(data)

        return asset

    def remove(self, asset_id):
        data = self._load()
        assets = data.get("assets", [])

        new_assets = [
            asset for asset in assets
            if asset.get("id") != asset_id
        ]

        if len(new_assets) == len(assets):
            raise AssetManagerError(
                f"Asset '{asset_id}' was not found."
            )

        data["assets"] = new_assets
        self._save(data)

        return True

    def set_enabled(self, asset_id, enabled):
        data = self._load()

        for asset in data.get("assets", []):
            if asset.get("id") == asset_id:
                asset["enabled"] = bool(enabled)
                self._save(data)
                return asset

        raise AssetManagerError(
            f"Asset '{asset_id}' was not found."
        )

    def get(self, asset_id):
        for asset in self.list_assets():
            if asset.get("id") == asset_id:
                return asset

        return None
