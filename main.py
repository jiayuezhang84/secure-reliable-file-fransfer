import argparse
from config import load_config
from src.client import run_client
from src.server import run_server


def main():
    parser = argparse.ArgumentParser(description="Secure Reliable File Transfer")

    parser.add_argument(
        "--mode",
        choices=["client", "server"],
        required=True,
        help="Run as client or server"
    )

    parser.add_argument(
        "--config",
        default="config_phase2.json",
        help="Path to configuration file"
    )

    parser.add_argument(
        "--file",
        help="Filename to request (client mode only)"
    )

    # Attack mode flag — used to test security properties during demo
    # --attack tamper  : flips bits in the first DATA packet (tests AEAD integrity)
    # --attack replay  : resends an old DATA packet after transfer (tests replay protection)
    # --attack inject  : sends a random garbage packet mid-transfer (tests AEAD rejection)
    parser.add_argument(
        "--attack",
        choices=["tamper", "replay", "inject"],
        default=None,
        help="Enable a built-in attack mode for security testing (server only)"
    )

    args = parser.parse_args()

    cfg = load_config(args.config)

    if args.mode == "server":
        # Pass the attack mode into the server so it knows what to simulate
        run_server(cfg, attack_mode=args.attack)

    elif args.mode == "client":
        if not args.file:
            parser.error("--file is required in client mode")
        run_client(cfg, args.file)


if __name__ == "__main__":
    main()