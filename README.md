# WiFi Safety Checker

A small local web app (Flask, macOS) that inspects the WiFi networks in
range and rates how safe each one is based on the encryption it
advertises. It's a defensive/educational security tool — it reads only
the metadata macOS already exposes and never attempts to crack, attack,
or gain unauthorized access to any network.

## What it does

- **Scans networks in range** using macOS's built-in
  `system_profiler SPAirPortDataType`, listing the network you're
  currently connected to plus other visible networks.
- **Rates each network's safety** from the encryption mode it
  advertises:

  | Level    | Meaning |
  |----------|---------|
  | `best`   | WPA3 — strongest available |
  | `safe`   | WPA2 — currently acceptable |
  | `caution`| WPA — outdated, known vulnerabilities |
  | `unsafe` | Open (no encryption) or WEP (trivially crackable) |
  | `unknown`| Security type could not be determined |

- **Shows a saved password only for your own known networks.** The
  "Get saved password" button reads a password **already stored in this
  Mac's Keychain** via the `security` CLI. macOS shows its native
  Allow / Always Allow / Deny prompt — that prompt is the real
  authorization gate, and this app cannot bypass it. It works only for
  networks this Mac has connected to and saved before.

## What it explicitly does NOT do

- No password cracking, brute-forcing, or deauth/handshake capture.
- No connecting to or probing networks you aren't authorized to use.
- No access to other devices' or other users' credentials — only this
  Mac's own saved Keychain entries, gated by the OS permission prompt.

It's designed to answer "is the coffee-shop WiFi I'm about to join
encrypted?" and "what did I save for my home network?" — not to attack
anything.

## Architecture

| File | Role |
|------|------|
| [app.py](app.py) | Flask server; routes `/`, `/api/scan`, `/api/password` |
| [wifi_scan.py](wifi_scan.py) | Parses `system_profiler` JSON, classifies security, builds safety ratings |
| [keychain.py](keychain.py) | Looks up a network's saved password via the macOS `security` CLI |
| [templates/index.html](templates/index.html) | Single-page UI: current network, in-range networks, per-network password lookup |

## Requirements

- **macOS** (relies on `system_profiler` and the `security` CLI — not
  portable to Linux/Windows).
- Python 3.9+
- Flask

## Setup & run

```bash
cd wifi-safety-checker
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open http://127.0.0.1:5050

### Note on redacted SSIDs

Recent macOS versions hide network names (showing `<redacted>`) from
`system_profiler` unless the requesting app has **Location** permission.
If you see redacted names, grant Location access to your terminal app
under **System Settings → Privacy & Security → Location Services**, then
reload the page. The app shows an in-page banner when this happens.

## Disclaimer

For educational and personal defensive use on networks you own or are
authorized to assess. You are responsible for complying with local laws
and network policies.
