from security_core.offensive.authorized_testing import (
    AuthorizedTesting,
    OffensiveSecurityError,
)


LOCAL_OPERATIONS = {
    "local_service_inventory",
    "local_port_inventory",
    "local_configuration_audit",
    "local_vulnerability_assessment",
    "local_evidence_collection",
}


class LocalTesting:
    """Authorized security testing interface for the local host."""

    def __init__(self):
        self.authorization = AuthorizedTesting()

    def authorize(self, asset_id, operation):
        if operation not in LOCAL_OPERATIONS:
            raise OffensiveSecurityError(
                f"Unsupported localhost operation: {operation}"
            )

        return self.authorization.prepare(
            asset_id,
            operation,
        )

    def available_operations(self):
        return sorted(LOCAL_OPERATIONS)
