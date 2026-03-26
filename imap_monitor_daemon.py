from __future__ import annotations

from skills.imap_monitor.skill import daemon_loop


def main() -> None:
    daemon_loop()


if __name__ == "__main__":
    main()
