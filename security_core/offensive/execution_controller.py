from dataclasses import dataclass
from datetime import datetime, timezone

from security_core.inventory.authorization import (
    AuthorizationEngine,
    AuthorizationError,
)

from security_core.offensive.capability_lock_registry import (
    CapabilityLockRegistry,
)

from security_core.offensive.release_policy import (
    ProducerReleasePolicy,
    ReleasePolicyError,
)

from security_core.integrity.manifest import verify_manifest
from security_core.safety.emergency_lockdown import EmergencyLockdown
from security_core.audit.audit_logger import SecurityAuditLogger


@dataclass(frozen=True)
class ExecutionRequest:
    mode: str
    capability: str
    asset_id: str
    parameters: dict


class OffensiveExecutionController:
    """
    Central safety boundary for Ghost offensive-security execution.

    Every high-risk capability is locked by default.

    Required safety gates:
      1. Integrity verification
      2. Emergency lockdown check
      3. Capability registration
      4. Producer cryptographic release
      5. Explicit capability release
      6. Explicit asset authorization
      7. Execution backend enabled

    The high-risk backend remains disabled in this build.
    """

    def __init__(self, authorization=None, release_policy=None, lock_registry=None):
        self.authorization = authorization or AuthorizationEngine()
        self.release_policy = release_policy or ProducerReleasePolicy()
        self.lock_registry = lock_registry or CapabilityLockRegistry()
        self.emergency_lockdown = EmergencyLockdown()
        self.audit_logger = SecurityAuditLogger()

        # Safety invariant: this remains False in the locked build.
        self.execution_backend_enabled = False

        self.history = []

    def status(self):
        integrity_ok, integrity_reason = verify_manifest()
        emergency = self.emergency_lockdown.status()
        release = self.release_policy.status()

        locked_capabilities = [
            item.capability
            for item in self.lock_registry.list_locked()
        ]

        return {
            "integrity_verified": integrity_ok,
            "integrity_reason": integrity_reason,
            "emergency_lockdown": emergency["locked"],
            "emergency_lockdown_reason": emergency["reason"],
            "lockdown": not integrity_ok or emergency["locked"],
            "authorization_required": True,
            "producer_release_verified": release["producer_release_verified"],
            "released_capabilities": release["released_capabilities"],
            "locked_capabilities": sorted(locked_capabilities),
            "execution_backend_enabled": self.execution_backend_enabled,
            "high_risk_execution_enabled": False,
            "locked": True,
            "verification": release["verification"],
        }

    def _audit(self, event, status, request, details=None):
        """
        Record a security event.

        Audit failure never enables execution. The operation remains blocked.
        """
        try:
            return self.audit_logger.record(
                event=event,
                status=status,
                capability=request.capability,
                asset_id=request.asset_id,
                details=details or {},
            )
        except Exception as exc:
            return {
                "audit_error": str(exc),
            }

    def _blocked(self, record, request, status, message, event):
        audit = self._audit(
            event=event,
            status=status,
            request=request,
            details={
                "message": message,
                "mode": request.mode,
            },
        )

        result = {
            **record,
            "status": status,
            "executed": False,
            "message": message,
            "audit_recorded": "audit_error" not in audit,
        }

        if "audit_error" in audit:
            result["audit_error"] = audit["audit_error"]

        return result

    def _authorization_check(self, request):
        try:
            self.authorization.require_authorization(
                request.asset_id,
                request.capability,
            )
            return True, "Asset authorization verified."
        except AuthorizationError as exc:
            return False, str(exc)

    def _release_check(self, request):
        try:
            status = self.release_policy.status()

            if not status["producer_release_verified"]:
                return False, status["verification"]

            if not self.release_policy.is_released(request.capability):
                return (
                    False,
                    "Capability is not included in the producer-signed release.",
                )

            return True, "Producer capability release verified."

        except ReleasePolicyError as exc:
            return False, str(exc)

    def prepare(self, request):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": request.mode,
            "capability": request.capability,
            "asset_id": request.asset_id,
            "parameters": dict(request.parameters),
            "status": "PREPARED",
        }

        self.history.append(record)

        self._audit(
            event="execution_request_prepared",
            status="PREPARED",
            request=request,
            details={
                "mode": request.mode,
            },
        )

        return record

    def execute(self, request):
        record = self.prepare(request)

        # Gate 0: audit-chain integrity
        audit_ok, audit_reason = self.audit_logger.verify_chain()

        if not audit_ok:
            return self._blocked(
                record,
                request,
                "BLOCKED_AUDIT_INTEGRITY",
                audit_reason,
                "audit_integrity_failure",
            )

        # Gate 1: integrity
        integrity_ok, integrity_reason = verify_manifest()

        if not integrity_ok:
            return self._blocked(
                record,
                request,
                "LOCKDOWN_INTEGRITY_FAILURE",
                integrity_reason,
                "integrity_failure",
            )

        # Gate 2: emergency lockdown
        emergency = self.emergency_lockdown.status()

        if emergency["locked"]:
            return self._blocked(
                record,
                request,
                "BLOCKED_EMERGENCY_LOCKDOWN",
                emergency["reason"],
                "emergency_lockdown_block",
            )

        # Gate 3: capability registration
        lock = self.lock_registry.get(request.capability)

        if lock is None:
            return self._blocked(
                record,
                request,
                "BLOCKED_UNKNOWN_CAPABILITY",
                "Unknown capability. Default-deny policy blocked execution.",
                "unknown_capability_block",
            )

        # Gate 4 + 5: producer release
        if lock.producer_release_required:
            released, release_reason = self._release_check(request)

            if not released:
                return self._blocked(
                    record,
                    request,
                    "BLOCKED_PRODUCER_RELEASE",
                    release_reason,
                    "producer_release_block",
                )

        # Gate 6: explicit asset authorization
        authorized, authorization_reason = self._authorization_check(request)

        if not authorized:
            return self._blocked(
                record,
                request,
                "BLOCKED_AUTHORIZATION",
                authorization_reason,
                "authorization_block",
            )

        # Gate 7: execution backend
        if not self.execution_backend_enabled:
            return self._blocked(
                record,
                request,
                "BACKEND_DISABLED",
                (
                    "All authorization gates passed, but the high-risk "
                    "execution backend is disabled in this build."
                ),
                "execution_backend_disabled",
            )

        # Safety invariant: no high-risk backend exists in this build.
        return self._blocked(
            record,
            request,
            "EXECUTION_NOT_IMPLEMENTED",
            "Execution backend is not implemented.",
            "execution_not_implemented",
        )

    def history_records(self):
        return list(self.history)
