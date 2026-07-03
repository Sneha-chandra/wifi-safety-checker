from flask import Flask, render_template, jsonify, request

from wifi_scan import scan_networks
from keychain import get_saved_password

app = Flask(__name__)


@app.route("/")
def index():
    current, others, redacted, error = scan_networks()
    return render_template(
        "index.html", current=current, others=others,
        redacted=redacted, error=error,
    )


@app.route("/api/scan")
def api_scan():
    current, others, redacted, error = scan_networks()
    return jsonify({"current": current, "others": others, "redacted": redacted, "error": error})


@app.route("/api/password", methods=["POST"])
def api_password():
    ssid = request.json.get("ssid", "").strip()
    if not ssid:
        return jsonify({"error": "Missing SSID"}), 400
    password, error = get_saved_password(ssid)
    return jsonify({"password": password, "error": error})


if __name__ == "__main__":
    app.run(debug=True, port=5050)
