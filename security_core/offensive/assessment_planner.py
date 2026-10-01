from dataclasses import dataclass
from typing import List

from security_core.offensive.capability_registry import (
    OffensiveCapabilityRegistry,
)


@dataclass(frozen=True)
class AssessmentStep:
    capability: str
    phase: str
    description: str


class OffensiveAssessmentPlanner:
    """
    Builds structured offensive-security assessment plans.

    This module plans work only. It does not execute tools.
    """

    def __init__(self):
        self.registry = OffensiveCapabilityRegistry()

    def plan_localhost(self):
        steps = [
            AssessmentStep(
                "local_service_inventory",
                "reconnaissance",
                "Inventory locally exposed services.",
            ),
            AssessmentStep(
                "local_port_inventory",
                "reconnaissance",
                "Inspect listening ports.",
            ),
            AssessmentStep(
                "local_configuration_audit",
                "assessment",
                "Review local security configuration.",
            ),
            AssessmentStep(
                "local_vulnerability_assessment",
                "assessment",
                "Assess identified local components for known weaknesses.",
            ),
        ]

        return steps

    def plan_network(self):
        steps = [
            AssessmentStep(
                "network_discovery",
                "reconnaissance",
                "Discover hosts within the permitted assessment scope.",
            ),
            AssessmentStep(
                "service_enumeration",
                "enumeration",
                "Identify exposed services.",
            ),
            AssessmentStep(
                "vulnerability_assessment",
                "assessment",
                "Assess discovered services for known weaknesses.",
            ),
            AssessmentStep(
                "web_security_assessment",
                "assessment",
                "Assess identified web applications and APIs.",
            ),
            AssessmentStep(
                "authenticated_security_assessment",
                "assessment",
                "Perform authorized authenticated checks where credentials are provided.",
            ),
        ]

        return steps

    def plan(self, mode):
        if mode == "localhost":
            return self.plan_localhost()

        if mode == "network":
            return self.plan_network()

        raise ValueError(
            "Unsupported offensive mode. "
            "Use 'localhost' or 'network'."
        )
