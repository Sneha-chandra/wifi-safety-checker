"""Reads WiFi network info from macOS via `system_profiler SPAirPortDataType`.

No password cracking: this only reads security metadata (encryption type,
channel, signal) that macOS already exposes for networks in range.
"""
import json
import subprocess

# Anything not WPA2/WPA3 is treated as unsafe. Order matters for display only.
SAFETY_RANK = {
    "open": ("unsafe", "Open network — no encryption, traffic can be read by anyone nearby"),
    "wep": ("unsafe", "WEP — broken encryption, crackable in minutes"),
    "wpa": ("caution", "WPA — outdated, has known vulnerabilities"),
    "wpa2": ("safe", "WPA2 — currently acceptable"),
    "wpa3": ("best", "WPA3 — strongest available"),
    "unknown": ("unknown", "Security type could not be determined"),
}


def _classify_security(raw_mode):
    if not raw_mode:
        return "open"
    mode = raw_mode.lower()
    if "wpa3" in mode:
        return "wpa3"
    if "wpa2" in mode:
        return "wpa2"
    if "wpa" in mode:
        return "wpa"
    if "wep" in mode:
        return "wep"
    if "none" in mode or "open" in mode:
        return "open"
    return "unknown"


def _network_entry(raw):
    security_key = _classify_security(raw.get("spairport_security_mode"))
    level, reason = SAFETY_RANK[security_key]
    return {
        "ssid": raw.get("_name", "Unknown"),
        "security_raw": raw.get("spairport_security_mode", "unknown").replace("spairport_security_mode_", ""),
        "security_key": security_key,
        "channel": raw.get("spairport_network_channel", "?"),
        "signal_noise": raw.get("spairport_signal_noise"),
        "safety_level": level,
        "safety_reason": reason,
    }


def scan_networks():
    """Returns (current_network, other_networks, redacted) from system_profiler."""
    try:
        out = subprocess.run(
            ["system_profiler", "SPAirPortDataType", "-json"],
            capture_output=True, text=True, timeout=15, check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        return None, [], False, f"Could not read WiFi info: {e}"

    try:
        data = json.loads(out.stdout)
        interfaces = data["SPAirPortDataType"][0]["spairport_airport_interfaces"]
        iface = next((i for i in interfaces if "spairport_current_network_information" in i or
                      "spairport_airport_other_local_wireless_networks" in i), interfaces[0])
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        return None, [], False, f"Unexpected system_profiler output: {e}"

    current_raw = iface.get("spairport_current_network_information")
    current = _network_entry(current_raw) if current_raw else None

    others_raw = iface.get("spairport_airport_other_local_wireless_networks", [])
    others = [_network_entry(n) for n in others_raw]

    all_names = [n["ssid"] for n in others] + ([current["ssid"]] if current else [])
    redacted = any(name == "<redacted>" for name in all_names)

    return current, others, redacted, None
