
import os
import json
import time
import hmac
import socket
import sqlite3
import ipaddress
from urllib.parse import urlparse

import requests
from flask import (
    Flask, request, jsonify, session,
    send_from_directory
)

app = Flask(__name__, static_folder="public")

app.secret_key = os.environ.get("SECRET_KEY", "")
ADMIN_PASSWORD = os.environ.get("TXG_PASSWORD", "")
DB_PATH = os.environ.get("DB_PATH", "/var/data/txg.db")

if not app.secret_key or not ADMIN_PASSWORD:
    print("WARNING: Set SECRET_KEY and TXG_PASSWORD in Render.")

os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS apis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                method TEXT NOT NULL DEFAULT 'POST'
            )
        """)


init_db()


def logged_in():
    return session.get("logged_in") is True


def valid_public_https_url(url):
    """Allow HTTPS URLs that resolve only to public IP addresses."""
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            return False
        if parsed.username or parsed.password:
            return False
        if parsed.port not in (None, 443):
            return False

        host = parsed.hostname
        if host.lower() == "localhost":
            return False

        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            addresses = [
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(
                    host, 443, type=socket.SOCK_STREAM
                )
            ]

        return bool(addresses) and all(
            addr.is_global for addr in addresses
        )
    except Exception:
        return False


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def home():
    return send_from_directory("public", "index.html")


@app.get("/api/session")
def check_session():
    return jsonify({"logged_in": logged_in()})


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))

    if not ADMIN_PASSWORD:
        return jsonify({"error": "Server password is not configured"}), 503

    if hmac.compare_digest(password, ADMIN_PASSWORD):
        session.clear()
        session["logged_in"] = True
        return jsonify({"ok": True})

    time.sleep(1)
    return jsonify({"error": "Incorrect password"}), 401


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/apis")
def list_apis():
    if not logged_in():
        return jsonify({"error": "Login required"}), 401

    with db() as con:
        rows = con.execute(
            "SELECT id, name, url, method FROM apis ORDER BY id DESC"
        ).fetchall()

    return jsonify([dict(row) for row in rows])


@app.post("/api/apis")
def add_api():
    if not logged_in():
        return jsonify({"error": "Login required"}), 401

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    url = str(data.get("url", "")).strip()
    method = str(data.get("method", "POST")).upper()

    if not name or len(name) > 60:
        return jsonify({"error": "Enter an API name (1–60 characters)"}), 400

    if len(url) > 2000 or not valid_public_https_url(url):
        return jsonify({
            "error": "Use a valid public HTTPS API URL on port 443"
        }), 400

    if method not in ("POST", "GET"):
        return jsonify({"error": "Method must be GET or POST"}), 400

    with db() as con:
        cur = con.execute(
            "INSERT INTO apis (name, url, method) VALUES (?, ?, ?)",
            (name, url, method)
        )
        api_id = cur.lastrowid

    return jsonify({"ok": True, "id": api_id})


@app.delete("/api/apis/<int:api_id>")
def delete_api(api_id):
    if not logged_in():
        return jsonify({"error": "Login required"}), 401

    with db() as con:
        cur = con.execute("DELETE FROM apis WHERE id = ?", (api_id,))

    if cur.rowcount == 0:
        return jsonify({"error": "API not found"}), 404

    return jsonify({"ok": True})


@app.post("/api/test/<int:api_id>")
def test_api(api_id):
    if not logged_in():
        return jsonify({"error": "Login required"}), 401

    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    if not isinstance(message, str) or len(message) > 5000:
        return jsonify({"error": "Message must be text, up to 5000 characters"}), 400

    with db() as con:
        api = con.execute(
            "SELECT * FROM apis WHERE id = ?", (api_id,)
        ).fetchone()

    if api is None:
        return jsonify({"error": "API not found"}), 404

    url = api["url"]

    # Recheck URL at request time too.
    if not valid_public_https_url(url):
        return jsonify({"error": "API URL failed the security check"}), 400

    started = time.time()

    try:
        headers = {
            "Accept": "*/*",
            "User-Agent": "TXG-Information/1.0"
        }

        if api["method"] == "GET":
            response = requests.get(
                url,
                params={"message": message},
                headers=headers,
                timeout=(5, 20),
                allow_redirects=False,
                stream=True
            )
        else:
            headers["Content-Type"] = "application/json"
            response = requests.post(
                url,
                json={"message": message},
                headers=headers,
                timeout=(5, 20),
                allow_redirects=False,
                stream=True
            )

        # Bound response size to protect the server.
        body = bytearray()
        for chunk in response.iter_content(chunk_size=8192):
            body.extend(chunk)
            if len(body) > 1_000_000:
                response.close()
                return jsonify({
                    "error": "Response exceeded the 1 MB display limit",
                    "status": response.status_code
                }), 502

        raw_text = bytes(body).decode(
            response.encoding or "utf-8", errors="replace"
        )

        return jsonify({
            "api": api["name"],
            "status": response.status_code,
            "content_type": response.headers.get("Content-Type", ""),
            "response": raw_text,
            "elapsed_ms": round((time.time() - started) * 1000)
        })

    except requests.RequestException as exc:
        return jsonify({
            "error": "Could not get a response from the API",
            "detail": str(exc)[:300]
        }), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
