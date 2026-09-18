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
    sub.add_parser("dump", help="print the full cloud device-list JSON (secrets redacted)")
    sub.add_parser("probe-controls",
                   help="safely discover the cloud set-action (toggles + reverts the status LED)")
    args = ap.parse_args(argv)
    cmd = args.cmd or "serve"
    try:
        if cmd == "discover":
            orchestrator.print_discovery()
        elif cmd == "dump":
            orchestrator.print_raw_devices()
        elif cmd == "probe-controls":
            orchestrator.probe_controls()
        else:
            orchestrator.serve()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
