#!/usr/bin/env python3
"""
castanet.py - Chromecast WiFi setup via Flask web UI
Port of castanet.sh to Python with a beautiful web interface.
"""

import json
import time
import base64
import subprocess
import threading
import requests
import urllib3
from flask import Flask, render_template, request, jsonify, Response, stream_with_context

# Disable SSL warnings for the self-signed Chromecast cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# --- Chromecast API helpers ---

CHROMECAST_PORT = 8443
TLS_OPTIONS = dict(verify=False)  # Chromecast uses self-signed cert

def cc_url(ip, path):
    return f"https://{ip}:{CHROMECAST_PORT}{path}"

def get_device_info(ip):
    r = requests.get(cc_url(ip, "/setup/eureka_info"), **TLS_OPTIONS, timeout=10)
    r.raise_for_status()
    return r.json()

def trigger_wifi_scan(ip):
    r = requests.post(cc_url(ip, "/setup/scan_wifi"), **TLS_OPTIONS, timeout=10)
    r.raise_for_status()

def get_scan_results(ip):
    r = requests.get(cc_url(ip, "/setup/scan_results"), **TLS_OPTIONS, timeout=10)
    r.raise_for_status()
    return r.json()

def get_configured_networks(ip):
    r = requests.get(cc_url(ip, "/setup/configured_networks"), **TLS_OPTIONS, timeout=10)
    r.raise_for_status()
    return r.json()

def forget_network(ip, wpa_id):
    r = requests.post(
        cc_url(ip, "/setup/forget_wifi"),
        json={"wpa_id": wpa_id},
        **TLS_OPTIONS, timeout=10
    )
    r.raise_for_status()
    return r.json()

def set_device_info(ip, name=None, opt_in=None):
    payload = {}
    if name:
        payload["name"] = name
    if opt_in is not None:
        payload["opt_in"] = opt_in
    r = requests.post(
        cc_url(ip, "/setup/set_eureka_info"),
        json=payload,
        **TLS_OPTIONS, timeout=10
    )
    r.raise_for_status()

def encrypt_password(public_key_b64: str, password: str) -> str:
    """
    Encrypt WiFi password with Chromecast's RSA public key.
    Uses the same method as the original JS snippet by @thorleifjaocbsen.
    """
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    import struct

    # The Chromecast sends a raw RSA public key in base64 (DER SubjectPublicKeyInfo or PKCS#1)
    # We need to figure out which format and handle both.
    key_der = base64.b64decode(public_key_b64)

    # Try loading as SubjectPublicKeyInfo (DER) first, then PKCS#1
    try:
        public_key = load_der_public_key(key_der)
    except Exception:
        # Wrap in PKCS#1 RSAPublicKey header manually
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pem = (
            b"-----BEGIN RSA PUBLIC KEY-----\n"
            + base64.encodebytes(key_der)
            + b"-----END RSA PUBLIC KEY-----\n"
        )
        # Use subprocess to call openssl to convert PKCS#1 -> SubjectPublicKeyInfo
        result = subprocess.run(
            ["openssl", "rsa", "-RSAPublicKey_in", "-pubout"],
            input=pem, capture_output=True
        )
        public_key = load_pem_public_key(result.stdout)

    encrypted = public_key.encrypt(
        password.encode("utf-8"),
        asym_padding.PKCS1v15()
    )
    return base64.b64encode(encrypted).decode("utf-8")

def connect_wifi(ip, ssid, wpa_auth, wpa_cipher, enc_passwd):
    payload = {
        "ssid": ssid,
        "wpa_auth": wpa_auth,
        "wpa_cipher": wpa_cipher,
        "enc_passwd": enc_passwd,
    }
    r = requests.post(
        cc_url(ip, "/setup/connect_wifi"),
        json=payload,
        **TLS_OPTIONS, timeout=15
    )
    r.raise_for_status()

def save_wifi(ip):
    payload = {"keep_hotspot_until_connected": True}
    r = requests.post(
        cc_url(ip, "/setup/save_wifi"),
        json=payload,
        **TLS_OPTIONS, timeout=15
    )
    r.raise_for_status()


# --- Flask routes ---

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/device_info", methods=["POST"])
def api_device_info():
    data = request.get_json()
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    try:
        info = get_device_info(ip)
        return jsonify({"ok": True, "info": info})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/scan_wifi", methods=["POST"])
def api_scan_wifi():
    """Start a WiFi scan and stream progress via SSE."""
    data = request.get_json()
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP address required"}), 400

    def generate():
        try:
            yield f"data: {json.dumps({'step': 'scan_start', 'msg': 'Triggering WiFi scan on device...'})}\n\n"
            trigger_wifi_scan(ip)
            yield f"data: {json.dumps({'step': 'waiting', 'msg': 'Waiting 20 seconds for scan to complete...', 'seconds': 20})}\n\n"
            for i in range(20):
                time.sleep(1)
                yield f"data: {json.dumps({'step': 'tick', 'remaining': 19 - i})}\n\n"
            yield f"data: {json.dumps({'step': 'fetching', 'msg': 'Fetching scan results...'})}\n\n"
            networks = get_scan_results(ip)
            yield f"data: {json.dumps({'step': 'done', 'networks': networks})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'step': 'error', 'error': str(e)})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")

@app.route("/api/connect_wifi", methods=["POST"])
def api_connect_wifi():
    """Connect Chromecast to a WiFi network."""
    data = request.get_json()
    ip = data.get("ip", "").strip()
    ssid = data.get("ssid", "").strip()
    password = data.get("password", "")
    wpa_auth = data.get("wpa_auth")
    wpa_cipher = data.get("wpa_cipher")

    if not all([ip, ssid, password]):
        return jsonify({"ok": False, "error": "IP, SSID, and password are required"}), 400

    def generate():
        try:
            yield f"data: {json.dumps({'step': 'pubkey', 'msg': 'Fetching device public key...'})}\n\n"
            info = get_device_info(ip)
            pub_key = info.get("public_key")
            if not pub_key:
                yield f"data: {json.dumps({'step': 'error', 'error': 'Could not get public key from device'})}\n\n"
                return

            yield f"data: {json.dumps({'step': 'encrypt', 'msg': 'Encrypting WiFi password...'})}\n\n"
            enc_passwd = encrypt_password(pub_key, password)

            yield f"data: {json.dumps({'step': 'connect', 'msg': 'Sending connect command...'})}\n\n"
            connect_wifi(ip, ssid, wpa_auth, wpa_cipher, enc_passwd)

            yield f"data: {json.dumps({'step': 'save', 'msg': 'Saving WiFi configuration...'})}\n\n"
            save_wifi(ip)

            yield f"data: {json.dumps({'step': 'done', 'msg': 'WiFi configuration saved! Unplug Ethernet to activate WiFi.'})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'step': 'error', 'error': str(e)})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")

@app.route("/api/configured_networks", methods=["POST"])
def api_configured_networks():
    data = request.get_json()
    ip = data.get("ip", "").strip()
    try:
        nets = get_configured_networks(ip)
        return jsonify({"ok": True, "networks": nets})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/forget_network", methods=["POST"])
def api_forget_network():
    data = request.get_json()
    ip = data.get("ip", "").strip()
    wpa_id = data.get("wpa_id")
    try:
        forget_network(ip, wpa_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/set_device_name", methods=["POST"])
def api_set_device_name():
    data = request.get_json()
    ip = data.get("ip", "").strip()
    name = data.get("name", "").strip()
    crash = data.get("crash", False)
    stats = data.get("stats", False)
    opencast = data.get("opencast", False)
    try:
        set_device_info(ip, name=name, opt_in={"crash": crash, "stats": stats, "opencast": opencast})
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


if __name__ == "__main__":
    print("🎬 Castanet - Chromecast Setup Tool")
    print("   Open http://localhost:5000 in your browser")
    app.run(host="0.0.0.0", port=5002, debug=True)
