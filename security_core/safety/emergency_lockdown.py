import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
STATE_FILE = BASE_DIR / "security_core" / "safety" / "lockdown_state.json"


DEFAULT_STATE = {
    "version": 1,
    "locked": True,
    "reason": "Default safety state",
}


class EmergencyLockdown:
    """
    Global fail-closed safety control.

    High-risk execution must never proceed while this
    state is locked.
    """

    def __init__(self, state_file=STATE_FILE):
        self.state_file = Path(state_file)

    def _write(self, state):
        self.state_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.state_file.write_text(
            json.dumps(state, indent=2) + "\n",
            encoding="utf-8",
        )

    def _read(self):
        if not self.state_file.exists():
            self._write(dict(DEFAULT_STATE))

        try:
            return json.loads(
                self.state_file.read_text(
                    encoding="utf-8"
                )
            )
        except (OSError, json.JSONDecodeError):
            # Fail closed if the state cannot be read.
            return {
                "version": 1,
                "locked": True,
                "reason": "Invalid lockdown state",
            }

    def status(self):
        state = self._read()

        return {
            "locked": state.get("locked", True) is True,
            "reason": state.get(
                "reason",
                "Unknown lockdown state",
            ),
        }

    def is_locked(self):
        return self.status()["locked"]

    def require_unlocked(self):
        status = self.status()

        if status["locked"]:
            raise RuntimeError(
                "Emergency lockdown is active."
            )

        return True

    def lock(self, reason="Emergency lockdown activated"):
        state = {
            "version": 1,
            "locked": True,
            "reason": reason,
        }

        self._write(state)
        return state


if __name__ == "__main__":
    controller = EmergencyLockdown()
    status = controller.status()

    print("=== GHOST EMERGENCY LOCKDOWN ===")
    print(
        "LOCKED: "
        + ("YES" if status["locked"] else "NO")
    )
    print(f"Reason: {status['reason']}")
