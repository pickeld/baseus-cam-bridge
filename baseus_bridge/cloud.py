"""Baseus cloud client: log in and discover cameras + their P2P credentials.

Flow reverse-engineered from the Baseus Security app (com.baseus /
com.xmitech.xmapi):

  1. Baseus native login -> auth token
     POST https://baseus-<region>-auth-gw.baseussecurity.com/api/auth/account/login
  2. XMitech GetUserDeviceList (same token) -> devices, cameras, p2p_password, LAN IP

No credentials are stored on disk by this module; callers pass them in.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

# --- constants recovered from the decompiled app ---
RSA_PUB = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDACE9CZ0ZLsrlF0/QRxnhqufc
bAR2Y8CJXKVgGBHL8XyPuSPcUhqJGCO9UE7FlDsq1BFyuqx9iLs786SEAg5Bskk
Am6BttV5uXQSIFOxFjuz6PRueq++TiP9KCuPOspvWhVuZFJrajeyTVJ65sViiwm
njOUTt/60qJr8Gk4ZqCPwIDAQAB
-----END PUBLIC KEY-----"""

SIGN_SALT = "GSiPpcmX"
SIGN_PREFIX = "ipc#CElYvAkK#"
XM_APP_KEY = "YGnzWsirKf55MxrjG5"
XM_APP_SECRET = "Teyi6OmXJZxVDiZY4k"
XM_SERVICE_VERSION = "3.0"

AUTH_HOSTS = {
    "US": "https://baseus-us-auth-gw.baseussecurity.com",
    "EU": "https://baseus-eu-auth-gw.baseussecurity.com",
    "AU": "https://baseus-au-auth-gw.baseussecurity.com",
}
XM_HOST_BOOTSTRAP = "https://root.xmitech.net/v1/api/app/host"
REGION_CODE = {"US": 1, "EU": 44, "AU": 61}
XM_HOST_FALLBACK = {
    "US": "https://ipc-bu-us-gw-2.baseussecurity.com",
    "EU": "https://ipc-bu-eu-gw.baseussecurity.com",
    "AU": "https://ipc-bu-us-gw-2.baseussecurity.com",
}


class CloudError(RuntimeError):
    pass


# --- writable-control (set) discovery ---------------------------------------
# The cloud "set" operation for this binary-protocol device family is not
# publicly documented, so the exact Action name + body shape are discovered
# empirically (safely, with read-back + auto-revert) via ``probe-controls``.
# These candidates are the most likely XM open-platform conventions. Once a
# working pair is confirmed it can be pinned via env so controls "just work".
SET_ACTION_CANDIDATES = (
    "SetDeviceInfo",
    "SetDeviceConfig",
    "SetChildInfo",
    "OperateDevice",
    "DeviceControl",
    "SetDeviceParam",
    "SetDeviceParams",
    "SetIpcParam",
    "UpdateDeviceInfo",
    "SetDeviceProperty",
)
SET_SHAPE_CANDIDATES = (
    "flat_device_sn",   # {"device_sn": sn, <key>: value}
    "flat_sn",          # {"sn": sn, <key>: value}
    "params",           # {"device_sn": sn, "params": {<key>: value}}
    "device_info",      # {"device_sn": sn, "device_info": {<key>: value}}
    "key_value",        # {"device_sn": sn, "key": <key>, "value": value}
    "child",            # {"device_sn": base, "channel": ch, "child_sn": sn, <key>: value}
)
# Pin the confirmed pair here (or via env) after running the probe.
CONFIRMED_SET_ACTION = os.environ.get("BASEUS_SET_ACTION") or ""
CONFIRMED_SET_SHAPE = os.environ.get("BASEUS_SET_SHAPE") or ""


def _md5hex(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()


def _sha1hex(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


def slugify(name: str, fallback: str = "cam") -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return s or fallback


@dataclass
class Camera:
    """A single streamable camera on a device."""
    name: str
    slug: str
    host: str            # LAN IP of the device/base to reach over PPPP
    device_sn: str       # PPPP login username (base or standalone device SN)
    p2p_password: str    # PPPP password + AES key material
    channel: int         # camera channel on the base (0 for standalone)
    camera_sn: str       # SN of the actual camera
    device_did: str = ""
    model: str = ""
    online: bool = True
    is_homebase_child: bool = False
    extra: dict = field(default_factory=dict)

    def redacted(self) -> dict:
        d = self.__dict__.copy()
        d["p2p_password"] = "***"
        d.pop("extra", None)
        return d


class BaseusCloud:
    def __init__(self, account: str, password: str, region: str = "AUTO",
                 country_code: str = "1", timeout: int = 25):
        if not account or not password:
            raise CloudError("account and password are required")
        self.account = account
        self.password = password
        self.region = (region or "AUTO").upper()
        self.country_code = str(country_code)
        self.timeout = timeout
        self.token: Optional[str] = None
        self.resolved_region: Optional[str] = None
        self._host: Optional[str] = None
        self._session = requests.Session()

    # --- auth ---
    def _rsa_pw(self) -> str:
        key = RSA.import_key(RSA_PUB)
        return base64.b64encode(PKCS1_v1_5.new(key).encrypt(self.password.encode())).decode()

    def _login_once(self, region: str):
        url = f"{AUTH_HOSTS[region]}/api/auth/account/login"
        body = json.dumps(
            {"type": 0, "account": self.account, "password": self._rsa_pw()},
            separators=(",", ":"),
        ).encode()
        ts = str(int(time.time() * 1000))
        sign = SIGN_PREFIX + _sha1hex((SIGN_SALT + _md5hex(body).upper() + ts).encode())
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "platform": "1", "auth": "", "region": region, "appType": "40",
            "lang": "en", "appVersion": "1.11.0", "versionCode": "52",
            "brand": "Google", "model": "Pixel", "osVersion": "14",
            "channel": "google", "sign": sign, "timestamp": ts,
        }
        r = self._session.post(url, params={"countryCode": self.country_code},
                               data=body, headers=headers, timeout=self.timeout)
        try:
            data = r.json()
        except ValueError:
            snippet = (r.text or "").strip().replace("\n", " ")[:200]
            raise CloudError(
                f"login endpoint returned non-JSON (HTTP {r.status_code}) "
                f"from {region}: {snippet!r} -- check the account is a real "
                "Baseus login (not the placeholder) and the region."
            )
        return (data.get("data") or {}).get("auth"), data

    def login(self) -> str:
        regions = [self.region] if self.region in AUTH_HOSTS else list(AUTH_HOSTS)
        last = None
        last_err = None
        for reg in regions:
            try:
                token, data = self._login_once(reg)
            except CloudError as err:
                last_err = err
                continue
            if token:
                self.token = token
                self.resolved_region = reg
                return token
            last = data
            msg = data.get("message") or data.get("msg")
            if data.get("code") in (100209,) or (msg and "password" in str(msg).lower()):
                break
        if last is None and last_err is not None:
            raise last_err
        msg = (last or {}).get("message") or (last or {}).get("msg") or "unknown error"
        raise CloudError(f"login failed: {msg} (check account/password/region)")

    # --- device data ---
    def _xm_headers(self, action: Optional[str]) -> dict:
        ts = str(int(time.time() * 1000))
        h = {
            "User-Agent": "okhttp/4", "Timestamp": ts, "Version": XM_SERVICE_VERSION,
            "SecretId": XM_APP_KEY,
            "Signature": _md5hex((ts + XM_APP_KEY + XM_APP_SECRET).encode()),
            "Lang": "en", "RequestId": str(uuid.uuid4()), "Authorization": self.token,
            "Content-Type": "application/json; charset=utf-8",
        }
        if action:
            h["Action"] = action
        return h

    def _resolve_host(self) -> str:
        region = self.resolved_region or "US"
        code = REGION_CODE.get(region, 1)
        ts = int(time.time() * 1000)
        body = json.dumps(
            {"code": code, "app_key": XM_APP_KEY,
             "sign": _md5hex((str(ts) + XM_APP_KEY + XM_APP_SECRET).encode()),
             "sign_ts": ts},
            separators=(",", ":"),
        ).encode()
        try:
            r = self._session.post(XM_HOST_BOOTSTRAP, headers=self._xm_headers(None),
                                   data=body, timeout=self.timeout)
            host = (r.json().get("payload") or {}).get("host")
            if host:
                return host
        except Exception:
            pass
        return XM_HOST_FALLBACK.get(region, XM_HOST_FALLBACK["US"])

    def raw_device_list(self) -> dict:
        if not self.token:
            self.login()
        if not self._host:
            self._host = self._resolve_host()
        r = self._session.post(self._host, headers=self._xm_headers("GetUserDeviceList"),
                               data=b"{}", timeout=self.timeout)
        return r.json()

    # --- writable controls ---
    def _xm_post(self, action: str, body_obj: dict) -> dict:
        """Signed XM request for an arbitrary Action (same envelope as reads)."""
        if not self.token:
            self.login()
        if not self._host:
            self._host = self._resolve_host()
        data = json.dumps(body_obj, separators=(",", ":")).encode()
        r = self._session.post(self._host, headers=self._xm_headers(action),
                               data=data, timeout=self.timeout)
        try:
            return r.json()
        except ValueError:
            return {"result": False, "code": -1,
                    "_http": r.status_code, "_text": (r.text or "")[:200]}

    @staticmethod
    def _set_body(shape: str, device_sn: str, key: str, value,
                  channel: Optional[int] = None, child_sn: Optional[str] = None) -> dict:
        if shape == "flat_device_sn":
            return {"device_sn": device_sn, key: value}
        if shape == "flat_sn":
            return {"sn": device_sn, key: value}
        if shape == "params":
            return {"device_sn": device_sn, "params": {key: value}}
        if shape == "device_info":
            return {"device_sn": device_sn, "device_info": {key: value}}
        if shape == "key_value":
            return {"device_sn": device_sn, "key": key, "value": value}
        if shape == "child":
            return {"device_sn": device_sn, "channel": int(channel or 0),
                    "child_sn": child_sn or device_sn, key: value}
        raise CloudError(f"unknown set-body shape {shape!r}")

    def set_device_param(self, device_sn: str, key: str, value, *,
                         action: Optional[str] = None, shape: Optional[str] = None,
                         channel: Optional[int] = None,
                         child_sn: Optional[str] = None) -> tuple[bool, dict]:
        """Attempt to set a device/camera parameter via the cloud.

        ``action``/``shape`` default to the confirmed pair (pinned constant or
        env). Returns ``(accepted, raw_response)`` where ``accepted`` only means
        the API reported success -- callers should verify by re-reading state.
        """
        action = action or CONFIRMED_SET_ACTION
        shape = shape or CONFIRMED_SET_SHAPE
        if not action or not shape:
            raise CloudError(
                "no confirmed set action/shape; run `python -m baseus_bridge "
                "probe-controls` first, then pin BASEUS_SET_ACTION/BASEUS_SET_SHAPE"
            )
        body = self._set_body(shape, device_sn, key, value, channel, child_sn)
        resp = self._xm_post(action, body)
        accepted = bool(resp.get("result")) and int(resp.get("code", 0) or 0) == 0
        return accepted, resp

    # --- high-level discovery ---
    def discover_cameras(self) -> list[Camera]:
        resp = self.raw_device_list()
        devices = ((resp.get("payload") or {}).get("device_list")) or []
        cams: list[Camera] = []
        used = set()

        def uniq(slug: str) -> str:
            base = slug
            i = 2
            while slug in used:
                slug = f"{base}-{i}"
                i += 1
            used.add(slug)
            return slug

        for dev in devices:
            info = dev.get("device_info") or {}
            plat = ((dev.get("device_extend") or {}).get("platform")) or {}
            host = info.get("lan") or ""
            device_sn = dev.get("device_sn") or ""
            p2p_password = plat.get("p2p_password") or ""
            device_did = plat.get("device_did") or ""
            channels = info.get("CameraChannel") or []
            children = {c.get("child_sn"): c for c in (dev.get("child_list") or [])}

            # Base-level telemetry shared by all paired cameras (storage, LED,
            # Wi-Fi SSID). Attached only to the first channel so we don't spawn
            # duplicate SD-card sensors for every camera on the same base.
            base_extra = {
                "storage": info.get("Storage", {}),
                "led_status": info.get("led_status"),
                "cur_ssid": info.get("cur_ssid"),
                "prompt_vol": info.get("prompt_vol"),
                "connection_mode": info.get("ConnectionMode"),
                "device_model": dev.get("device_model"),
                "device_name": dev.get("device_name"),
            }

            if channels:  # HomeStation with paired cameras
                for ch in channels:
                    cam_sn = ch.get("sn") or ""
                    child = children.get(cam_sn, {})
                    name = child.get("child_name") or f"{dev.get('device_name','cam')}-{ch.get('channel')}"
                    online = bool(child.get("child_online_status", 1))
                    extra = {
                        "child_info": child.get("child_info", {}),
                        "child_extend": child.get("child_extend", {}),
                    }
                    if int(ch.get("channel", 0)) == 0:
                        extra["base"] = base_extra
                    cams.append(Camera(
                        name=name, slug=uniq(slugify(name, cam_sn or "cam")),
                        host=host, device_sn=device_sn, p2p_password=p2p_password,
                        channel=int(ch.get("channel", 0)), camera_sn=cam_sn,
                        device_did=device_did, model=ch.get("model") or "",
                        online=online, is_homebase_child=True,
                        extra=extra,
                    ))
            else:  # standalone camera == the device itself
                name = dev.get("device_name") or device_sn
                cams.append(Camera(
                    name=name, slug=uniq(slugify(name, device_sn or "cam")),
                    host=host, device_sn=device_sn, p2p_password=p2p_password,
                    channel=0, camera_sn=device_sn, device_did=device_did,
                    model=dev.get("device_model") or "",
                    online=bool(dev.get("online_status", 1)), is_homebase_child=False,
                    extra={"device_info": info},
                ))
        return cams
