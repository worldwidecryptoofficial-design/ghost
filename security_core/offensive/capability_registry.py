from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Capability:
    name: str
    category: str
    mode: str
    description: str


CAPABILITIES: List[Capability] = [
    Capability(
        "local_service_inventory",
        "reconnaissance",
        "localhost",
        "Inventory services exposed by the local host.",
    ),
    Capability(
        "local_port_inventory",
        "reconnaissance",
        "localhost",
        "Inspect locally listening ports.",
    ),
    Capability(
        "local_configuration_audit",
        "assessment",
        "localhost",
        "Assess local security configuration.",
    ),
    Capability(
        "local_vulnerability_assessment",
        "assessment",
        "localhost",
        "Assess the local environment for known security weaknesses.",
    ),
    Capability(
        "network_discovery",
        "reconnaissance",
        "network",
        "Discover hosts within an authorized network scope.",
    ),
    Capability(
        "service_enumeration",
        "reconnaissance",
        "network",
        "Identify services exposed by an authorized target.",
    ),
    Capability(
        "web_security_assessment",
        "assessment",
        "network",
        "Assess authorized web applications and APIs.",
    ),
    Capability(
        "vulnerability_assessment",
        "assessment",
        "network",
        "Assess authorized targets for known vulnerabilities.",
    ),
    Capability(
        "authenticated_security_assessment",
        "assessment",
        "network",
        "Perform authorized authenticated security checks.",
    ),
]


class OffensiveCapabilityRegistry:
    def list_all(self):
        return list(CAPABILITIES)

    def list_mode(self, mode):
        return [
            capability
            for capability in CAPABILITIES
            if capability.mode == mode
        ]

    def get(self, name):
        for capability in CAPABILITIES:
            if capability.name == name:
                return capability
        return None
