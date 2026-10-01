import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


EVIDENCE_DIR = Path(__file__).resolve().parent / "records"


class FindingEngine:
    """Create and persist structured security findings."""

    def __init__(self, evidence_dir=EVIDENCE_DIR):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        asset_id,
        capability,
        title,
        severity,
        description,
        evidence=None,
        remediation=None,
    ):
        allowed_severities = {
            "info",
            "low",
            "medium",
            "high",
            "critical",
        }

        if severity not in allowed_severities:
            raise ValueError(
                f"Invalid severity: {severity}"
            )

        finding = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "asset_id": asset_id,
            "capability": capability,
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence or [],
            "remediation": remediation or "",
        }

        path = self.evidence_dir / f"{finding['id']}.json"

        with path.open("w", encoding="utf-8") as f:
            json.dump(finding, f, indent=2)
            f.write("\n")

        return finding

    def list_findings(self):
        findings = []

        for path in sorted(self.evidence_dir.glob("*.json")):
            try:
                with path.open("r", encoding="utf-8") as f:
                    findings.append(json.load(f))
            except (OSError, json.JSONDecodeError):
                continue

        return findings

    def get(self, finding_id):
        path = self.evidence_dir / f"{finding_id}.json"

        if not path.exists():
            return None

        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
