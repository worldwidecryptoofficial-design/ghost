from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class CapabilityLock:
    tool: str
    capability: str
    risk_level: str
    producer_release_required: bool
    description: str


LOCKED_CAPABILITIES: List[CapabilityLock] = [
    # Nmap
    CapabilityLock(
        "nmap",
        "nmap_high_risk",
        "high",
        True,
        "High-risk Nmap operations.",
    ),

    # Masscan
    CapabilityLock(
        "masscan",
        "masscan_high_risk",
        "high",
        True,
        "High-risk Masscan operations.",
    ),

    # SQLmap
    CapabilityLock(
        "sqlmap",
        "sqlmap_high_risk",
        "critical",
        True,
        "High-risk SQLmap operations.",
    ),

    # Hydra
    CapabilityLock(
        "hydra",
        "hydra_high_risk",
        "critical",
        True,
        "High-risk authentication-testing operations.",
    ),

    # Metasploit
    CapabilityLock(
        "metasploit",
        "metasploit_high_risk",
        "critical",
        True,
        "High-risk Metasploit operations.",
    ),

    # Aircrack-ng
    CapabilityLock(
        "aircrack-ng",
        "aircrack_high_risk",
        "high",
        True,
        "High-risk wireless-security operations.",
    ),

    # Hashcat
    CapabilityLock(
        "hashcat",
        "hashcat_high_risk",
        "high",
        True,
        "High-risk password-audit operations.",
    ),

    # John
    CapabilityLock(
        "john",
        "john_high_risk",
        "high",
        True,
        "High-risk password-audit operations.",
    ),
]


class CapabilityLockRegistry:
    """Central registry for Ghost high-risk capability locks."""

    def __init__(self):
        self._locks: Dict[str, CapabilityLock] = {
            item.capability: item
            for item in LOCKED_CAPABILITIES
        }

    def get(self, capability: str):
        return self._locks.get(capability)

    def is_locked(self, capability: str) -> bool:
        item = self.get(capability)
        return item is not None and item.producer_release_required

    def requires_producer_release(self, capability: str) -> bool:
        return self.is_locked(capability)

    def list_locked(self) -> List[CapabilityLock]:
        return list(self._locks.values())

    def tools(self) -> List[str]:
        return sorted({
            item.tool
            for item in self._locks.values()
        })
