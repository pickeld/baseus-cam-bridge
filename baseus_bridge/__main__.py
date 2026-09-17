"""CLI: ``python -m baseus_bridge <serve|discover>``."""
import argparse
import sys

from . import orchestrator


def main(argv=None):
    ap = argparse.ArgumentParser(prog="baseus_bridge",
                                 description="Serve Baseus cameras over RTSP/HLS/WebRTC")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="discover cameras and run the MediaMTX server (default)")
    sub.add_parser("discover", help="log in and print discovered cameras (secrets redacted)")
    args = ap.parse_args(argv)
    cmd = args.cmd or "serve"
    try:
        if cmd == "discover":
            orchestrator.print_discovery()
        else:
            orchestrator.serve()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
