"""MQTT ``WatchDevice`` wake for battery cameras.

Battery cameras sleep and drop off the P2P servers. Before live view the
official app publishes a ``WatchDevice`` action on the account's MQTT broker
(credentials come from the XM ``GetUserMQTTS`` call) and waits for the
correlated reply. This is a wake request, not a settings write.

Credentials, topics and device identifiers are never logged.
"""
from __future__ import annotations

import json
import secrets
import ssl
import threading
import time

import paho.mqtt.client as mqtt

REQUIRED_FIELDS = ("host", "port", "client_id", "username", "password", "publish", "subscribe")


class WakeError(RuntimeError):
    pass


def wants_tls(settings: dict) -> bool:
    """Honor an explicit ssl/tls flag; otherwise TLS unless the port is 1883."""
    for key in ("ssl", "tls", "use_ssl", "use_tls", "is_ssl", "enable_ssl"):
        if key in settings:
            value = settings[key]
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "ssl", "tls"}
            return bool(value)
    try:
        return int(settings.get("port")) != 1883
    except (TypeError, ValueError):
        return True


def wake_message(sn: str, product_id: str, wake_key: str, seq: str, timestamp_ms: int) -> dict:
    if not sn or not product_id or not wake_key:
        raise WakeError("wake requires sn, product_id and wake_key")
    return {
        "method": "Action",
        "actionId": "WatchDevice",
        "expands": {"productId": product_id, "sn": sn, "wake_key": wake_key},
        "payload": {"timestamp": timestamp_ms, "mode": 1},
        "seq": str(seq),
    }


def wake_reply(value, seq: str, retained: bool):
    """Return the bool result of *our* WatchDevice reply, else None."""
    if retained or not isinstance(value, dict) or str(value.get("seq")) != seq:
        return None
    if value.get("actionId") != "WatchDevice" or not isinstance(value.get("result"), bool):
        return None
    return value["result"]


def wake_camera(settings: dict, sn: str, product_id: str, wake_key: str,
                timeout: float = 30, abort=None, client_factory=None) -> None:
    """Publish WatchDevice and wait for the correlated reply (PUBACK is not enough).

    ``abort`` is an optional callable; when it returns true the wait stops.
    Raises :class:`WakeError` on any failure.
    """
    for key in REQUIRED_FIELDS:
        if key == "port":
            continue
        if not isinstance(settings.get(key), str) or not settings[key]:
            raise WakeError(f"MQTT config missing field {key}")
    host = settings["host"]
    if "://" in host or "/" in host:
        raise WakeError("MQTT host must be a hostname, not a URL")
    try:
        port = int(settings["port"])
    except (KeyError, TypeError, ValueError) as exc:
        raise WakeError("MQTT port is invalid") from exc

    seq = str(secrets.randbelow(1_000_000_000))
    connected, subscribed, replied = threading.Event(), threading.Event(), threading.Event()
    result = {"connect": False, "subscribe": False, "wake": False}

    if client_factory is None:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=settings["client_id"],
                             clean_session=True, protocol=mqtt.MQTTv311,
                             reconnect_on_failure=False)
    else:
        client = client_factory(settings)
    client.username_pw_set(settings["username"], settings["password"])
    if wants_tls(settings):
        client.tls_set(cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)

    def on_connect(_c, _u, _f, reason, _p):
        result["connect"] = not reason.is_failure
        connected.set()

    def on_subscribe(_c, _u, _mid, reasons, _p):
        result["subscribe"] = bool(reasons) and all(not r.is_failure for r in reasons)
        subscribed.set()

    def on_message(_c, _u, message):
        try:
            value = json.loads(message.payload)
        except (ValueError, UnicodeError):
            return
        answer = wake_reply(value, seq, message.retain)
        if answer is not None:
            result["wake"] = answer
            replied.set()

    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    deadline = time.monotonic() + timeout

    def wait_for(event, what: str) -> None:
        while True:
            if abort is not None and abort():
                raise WakeError("aborted")
            left = deadline - time.monotonic()
            if left <= 0:
                raise WakeError(f"{what} not confirmed")
            if event.wait(min(0.2, left)):
                return

    try:
        client.connect(host, port, keepalive=60)
        client.loop_start()
        wait_for(connected, "MQTT connect")
        if not result["connect"]:
            raise WakeError("MQTT connect refused")
        rc, _mid = client.subscribe(settings["subscribe"], qos=1)
        if rc != mqtt.MQTT_ERR_SUCCESS:
            raise WakeError("MQTT subscribe failed")
        wait_for(subscribed, "MQTT subscribe")
        if not result["subscribe"]:
            raise WakeError("MQTT subscribe refused")
        payload = wake_message(sn, product_id, wake_key, seq, int(time.time() * 1000))
        client.publish(settings["publish"], json.dumps(payload, separators=(",", ":")).encode(),
                       qos=2, retain=False)
        wait_for(replied, "WatchDevice reply")
        if not result["wake"]:
            raise WakeError("WatchDevice rejected")
    except (OSError, ValueError) as exc:
        raise WakeError(f"MQTT transport: {type(exc).__name__}") from None
    finally:
        try:
            client.disconnect()
        finally:
            client.loop_stop()
