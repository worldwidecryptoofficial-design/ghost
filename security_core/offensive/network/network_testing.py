from security_core.offensive.authorized_testing import (
    AuthorizedTesting,
    OffensiveSecurityError,
)


NETWORK_OPERATIONS = {
    "network_discovery",
    "service_enumeration",
    "vulnerability_assessment",
    "web_security_assessment",
    "authenticated_security_assessment",
    "network_evidence_collection",
}


class NetworkTesting:
    """Authorized penetration-testing interface for network targets."""

    def __init__(self):
        self.authorization = AuthorizedTesting()

    def authorize(self, asset_id, operation):
        if operation not in NETWORK_OPERATIONS:
            raise OffensiveSecurityError(
                f"Unsupported network operation: {operation}"
            )

        return self.authorization.prepare(
            asset_id,
            operation,
        )

    def available_operations(self):
        return sorted(NETWORK_OPERATIONS)
