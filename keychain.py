"""Looks up a WiFi password already saved in this Mac's own Keychain.

This is NOT cracking: it only works for networks this Mac has connected to
before and saved credentials for. macOS will show its own native Keychain
access prompt (Allow/Always Allow/Deny) — that prompt is the actual
authorization, this code cannot bypass it.
"""
import subprocess


def get_saved_password(ssid):
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-D", "AirPort network password",
             "-a", ssid, "-w"],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return None, "Timed out waiting for Keychain authorization."

    if result.returncode == 0:
        return result.stdout.strip(), None

    stderr = result.stderr.strip()
    if "could not be found" in stderr.lower():
        return None, "No saved password for this network on this Mac."
    if "denied" in stderr.lower() or "auth" in stderr.lower():
        return None, "Keychain access was denied."
    return None, f"Keychain lookup failed: {stderr or 'unknown error'}"
