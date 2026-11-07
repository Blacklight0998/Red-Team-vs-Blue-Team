# Red Team contribution represented in this group repository: Andy Vega Araya.
# Executable logic preserved from the supplied Red Team module.
from pathlib import Path

AUTHORIZED_TARGET_FILE = Path(__file__).parent.parent / "authorized_target.txt"


def confirm_authorized_target(target):
    if not AUTHORIZED_TARGET_FILE.exists():
        print(f"[auth] Missing {AUTHORIZED_TARGET_FILE.name}. Add one line with the authorized target.")
        raise SystemExit(1)

    authorized = AUTHORIZED_TARGET_FILE.read_text(encoding="utf-8").strip()

    if target != authorized:
        print(f"[auth] '{target}' does not match the authorized target in {AUTHORIZED_TARGET_FILE.name}.")
        raise SystemExit(1)

    answer = input(f"Confirm you are authorized to test '{target}'. Type 'yes' to continue: ").strip().lower()
    if answer != "yes":
        print("[auth] Not confirmed.")
        raise SystemExit(1)
