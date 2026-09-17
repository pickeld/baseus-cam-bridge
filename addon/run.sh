#!/usr/bin/env python3
"""Home Assistant add-on entrypoint.

Reads the add-on options straight from /data/options.json (written by
Supervisor) and starts the bridge. This avoids any dependency on the
Supervisor API / bashio, which requires extra permissions.
"""
import json
import os
import sys

OPTIONS_FILE = "/data/options.json"


def main() -> None:
    opts = {}
    try:
        with open(OPTIONS_FILE, encoding="utf-8") as fh:
            opts = json.load(fh)
    except FileNotFoundError:
        print(f"WARN: {OPTIONS_FILE} not found; using defaults.", file=sys.stderr)
    except (OSError, ValueError) as err:
        print(f"WARN: could not read {OPTIONS_FILE}: {err}", file=sys.stderr)

    account = str(opts.get("account", "")).strip()
    password = str(opts.get("password", ""))
    if not account or not password:
        print(
            "FATAL: Set your Baseus 'account' and 'password' in the "
            "add-on Configuration tab, then restart.",
            file=sys.stderr,
        )
        sys.exit(1)

    os.environ["BASEUS_ACCOUNT"] = account
    os.environ["BASEUS_PASSWORD"] = password
    os.environ["BASEUS_REGION"] = str(opts.get("region", "AUTO"))
    os.environ["BASEUS_COUNTRYCODE"] = str(opts.get("country_code", "1"))
    os.environ["BASEUS_FRAMERATE"] = str(opts.get("framerate", 25))
    os.environ["BASEUS_INCLUDE_OFFLINE"] = "1" if opts.get("include_offline", True) else "0"

    print(
        "Starting Baseus Cam Bridge (RTSP :8554, HLS :8888, WebRTC :8889)...",
        file=sys.stderr,
        flush=True,
    )
    # Hand off to the bridge; orchestrator.serve() execs MediaMTX and blocks.
    from baseus_bridge import orchestrator

    orchestrator.serve()


if __name__ == "__main__":
    main()
