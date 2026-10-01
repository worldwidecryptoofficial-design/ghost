from security_core.inventory.authorization import (
    AuthorizationEngine,
    AuthorizationError,
)


class OffensiveSecurityError(Exception):
    """Raised when an offensive-security operation is rejected."""
    pass


class AuthorizedTesting:
    """
    Authorization gate for Ghost's offensive-security subsystem.

    No security operation is executed here. This layer determines
    whether an operation is permitted for an explicitly authorized
    asset before an execution module is allowed to proceed.
    """

    def __init__(self):
        self.authorization = AuthorizationEngine()

    def check(self, asset_id, operation):
        try:
            self.authorization.require_authorization(
                asset_id,
                operation,
            )
        except AuthorizationError as exc:
            raise OffensiveSecurityError(str(exc))

        return {
            "authorized": True,
            "asset_id": asset_id,
            "operation": operation,
            "execution_allowed": True,
        }

    def prepare(self, asset_id, operation):
        result = self.check(asset_id, operation)

        return {
            "status": "AUTHORIZED",
            "asset_id": result["asset_id"],
            "operation": result["operation"],
            "message": (
                "Operation passed authorization. "
                "No execution has been performed."
            ),
        }
