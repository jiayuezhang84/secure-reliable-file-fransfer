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
        default="config.json",
        help="Path to configuration file"
    )

    parser.add_argument(
        "--file",
        help="Filename to request (client mode only)"
    )

    args = parser.parse_args()

    cfg = load_config(args.config)

    if args.mode == "server":
        run_server(cfg)

    elif args.mode == "client":
        run_client(cfg, args.file)


if __name__ == "__main__":
    main()