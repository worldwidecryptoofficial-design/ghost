#!/usr/bin/env python3

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security_core.offensive.execution_controller import (
    OffensiveExecutionController,
    ExecutionRequest,
)


class LockedExecutor:
    """
    Ghost high-risk execution boundary.

    Public-build guarantees:
    - No high-risk backend is enabled.
    - Missing/invalid producer release fails closed.
    - Unreleased capabilities fail closed.
    - Unauthorized assets fail closed.
    """

    def __init__(self):
        self.controller = OffensiveExecutionController()

    def status(self):
        return self.controller.status()

    def request(self, mode, capability, asset_id):
        request = ExecutionRequest(
            mode=mode,
            capability=capability,
            asset_id=asset_id,
            parameters={},
        )

        return self.controller.execute(request)


def self_test():
    executor = LockedExecutor()
    status = executor.status()

    checks = {
        "producer_release_verified":
            status["producer_release_verified"] is False,
        "execution_backend_enabled":
            status["execution_backend_enabled"] is False,
        "high_risk_execution_enabled":
            status["high_risk_execution_enabled"] is False,
        "locked":
            status["locked"] is True,
    }

    print("=== GHOST LOCKED EXECUTOR SELF-TEST ===")

    for name, passed in checks.items():
        print(f"{name}: {'PASS' if passed else 'FAIL'}")

    result = executor.request(
        mode="network",
        capability="vulnerability_assessment",
        asset_id="test-asset",
    )

    execution_blocked = result.get("executed") is False

    print(
        "execution_request_blocked: "
        + ("PASS" if execution_blocked else "FAIL")
    )

    all_passed = all(checks.values()) and execution_blocked

    print()
    print(
        "LOCKED_EXECUTOR_SELF_TEST: "
        + ("PASS" if all_passed else "FAIL")
    )

    return 0 if all_passed else 1


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return self_test()

    executor = LockedExecutor()
    status = executor.status()

    print("=== GHOST HIGH-RISK EXECUTOR ===")
    print(json.dumps(status, indent=2))

    if status["locked"]:
        print("\nSTATUS: LOCKED")
        print("No high-risk execution backend is enabled.")
        return 0

    print("\nSTATUS: CONTROLLED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
