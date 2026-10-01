import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security_core.offensive.capability_lock_registry import (
    CapabilityLockRegistry,
)
from security_core.offensive.execution_controller import (
    ExecutionRequest,
    OffensiveExecutionController,
)
from security_core.safety.emergency_lockdown import (
    EmergencyLockdown,
)
from security_core.audit.audit_logger import (
    SecurityAuditLogger,
)


def test_all_high_risk_capabilities_are_locked():
    registry = CapabilityLockRegistry()

    capabilities = registry.list_locked()

    assert capabilities, "No high-risk capabilities registered."

    for capability in capabilities:
        assert capability.producer_release_required is True


def test_unknown_capability_is_denied():
    controller = OffensiveExecutionController()

    request = ExecutionRequest(
        mode="network",
        capability="unknown_capability",
        asset_id="test-asset",
        parameters={},
    )

    result = controller.execute(request)

    assert result["executed"] is False


def test_emergency_lockdown_is_default_locked():
    with tempfile.TemporaryDirectory() as temp:
        state_file = Path(temp) / "lockdown.json"

        lockdown = EmergencyLockdown(
            state_file=state_file
        )

        status = lockdown.status()

        assert status["locked"] is True


def test_emergency_lockdown_blocks_execution():
    controller = OffensiveExecutionController()

    request = ExecutionRequest(
        mode="network",
        capability="nmap_high_risk",
        asset_id="test-asset",
        parameters={},
    )

    result = controller.execute(request)

    assert result["executed"] is False


def test_execution_backend_is_disabled():
    controller = OffensiveExecutionController()

    assert controller.execution_backend_enabled is False


def test_high_risk_execution_never_reports_enabled():
    controller = OffensiveExecutionController()

    status = controller.status()

    assert status["high_risk_execution_enabled"] is False


def test_default_release_has_no_capabilities():
    controller = OffensiveExecutionController()

    status = controller.status()

    assert status["released_capabilities"] == []


def test_audit_chain_integrity():
    with tempfile.TemporaryDirectory() as temp:
        audit_dir = Path(temp)

        logger = SecurityAuditLogger(
            audit_dir=audit_dir
        )

        first = logger.record(
            event="test_event_1",
            status="PASS",
            capability="test_capability",
            asset_id="test-asset",
        )

        second = logger.record(
            event="test_event_2",
            status="BLOCKED",
            capability="test_capability",
            asset_id="test-asset",
        )

        assert second["previous_hash"] == first["record_hash"]

        verified, reason = logger.verify_chain()

        assert verified is True, reason


def test_audit_chain_detects_tampering():
    with tempfile.TemporaryDirectory() as temp:
        audit_dir = Path(temp)

        logger = SecurityAuditLogger(
            audit_dir=audit_dir
        )

        logger.record(
            event="tamper_test",
            status="PASS",
            capability="test_capability",
            asset_id="test-asset",
        )

        path = next(audit_dir.glob("*.json"))

        data = json.loads(
            path.read_text(encoding="utf-8")
        )

        data["status"] = "MODIFIED"

        path.write_text(
            json.dumps(data, indent=2) + "\n",
            encoding="utf-8",
        )

        verified, reason = logger.verify_chain()

        assert verified is False
        assert "failed hash verification" in reason


def run_all():
    tests = [
        test_all_high_risk_capabilities_are_locked,
        test_unknown_capability_is_denied,
        test_emergency_lockdown_is_default_locked,
        test_emergency_lockdown_blocks_execution,
        test_execution_backend_is_disabled,
        test_high_risk_execution_never_reports_enabled,
        test_default_release_has_no_capabilities,
        test_audit_chain_integrity,
        test_audit_chain_detects_tampering,
    ]

    print("=== GHOST SECURITY REGRESSION TESTS ===")

    passed = 0

    for test in tests:
        try:
            test()
            print(f"PASS: {test.__name__}")
            passed += 1
        except Exception as exc:
            print(f"FAIL: {test.__name__}")
            print(f"      {exc}")

    print()
    print(f"Passed: {passed}/{len(tests)}")

    if passed != len(tests):
        print("SECURITY_REGRESSION_TEST: FAIL")
        return 1

    print("SECURITY_REGRESSION_TEST: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_all())
