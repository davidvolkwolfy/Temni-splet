"""
SRC — interno orodje za preverjanje razkritij (LeakOsint).

Tanek JSON proxy: frontend je statični HTML/CSS/JS (static/index.html),
ta strežnik pa hrani API token, preverja prijavo in beleži poizvedbe.

NAMEN: interna uporaba za pooblaščene preiskave (IR / threat intel).
Ni namenjeno javnemu dostopu. Deploy na interni mreži / za VPN.
"""

import functools
import json
import logging
import os
import sys
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, request, send_from_directory, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# --- Konfiguracija ---------------------------------------------------------

SECRET_KEY = os.getenv("SECRET_KEY")
LEAKOSINT_TOKEN = os.getenv("LEAKOSINT_TOKEN")
USERS_FILE = os.getenv("USERS_FILE", "users.json")
AUDIT_LOG = os.getenv("AUDIT_LOG", "audit.log")

API_URL = "https://leakosintapi.com/"
REQUEST_TIMEOUT = 20
DEFAULT_LIMIT = int(os.getenv("SEARCH_LIMIT", "100"))
DEFAULT_LANG = os.getenv("SEARCH_LANG", "en")
COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"


# --- CLI pomočnik:  python app.py hash <geslo> -----------------------------
if __name__ == "__main__" and len(sys.argv) >= 3 and sys.argv[1] == "hash":
    print(generate_password_hash(sys.argv[2]))
    sys.exit(0)


# --- Preverbe ob zagonu ----------------------------------------------------

if not SECRET_KEY:
    raise RuntimeError("Manjka SECRET_KEY (za podpisovanje sej).")
if not LEAKOSINT_TOKEN:
    raise RuntimeError("Manjka LEAKOSINT_TOKEN (API ključ storitve LeakOsint).")


def load_users(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            users = json.load(fh)
        if not isinstance(users, dict) or not users:
            raise ValueError
        return users
    except FileNotFoundError:
        raise RuntimeError(
            f"Manjka datoteka z uporabniki: {path}. "
            f"Ustvari jo z: python app.py hash <geslo>"
        )
    except (ValueError, json.JSONDecodeError):
        raise RuntimeError(f"Neveljavna vsebina {path} (pričakovan JSON: user -> hash).")


USERS = load_users(USERS_FILE)


# --- Beleženje (audit) -----------------------------------------------------
# OPOZORILO: audit dnevnik vsebuje iskalne pojme (lahko osebni podatki).
# Datoteko zaščiti in hrani skladno z internimi pravili / GDPR.

_audit = logging.getLogger("audit")
_audit.setLevel(logging.INFO)
_audit_handler = logging.FileHandler(AUDIT_LOG, encoding="utf-8")
_audit_handler.setFormatter(logging.Formatter("%(message)s"))
_audit.addHandler(_audit_handler)


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "-").split(",")[0].strip()


def audit(event, **fields):
    parts = [
        datetime.now(timezone.utc).isoformat(timespec="seconds"),
        f"event={event}",
        f"user={session.get('user', '-')}",
        f"ip={_client_ip()}",
    ]
    for k, v in fields.items():
        parts.append(f'{k}="{v}"')
    _audit.info(" ".join(parts))


# --- Flask -----------------------------------------------------------------

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["500 per day"],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
)


def api_login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "Potrebna je prijava."}), 401
        return view(*args, **kwargs)
    return wrapped


def clamp_limit(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        value = DEFAULT_LIMIT
    return max(100, min(value, 10000))


def query_leakosint(query, limit, lang):
    payload = {"token": LEAKOSINT_TOKEN, "request": query, "limit": limit, "lang": lang}
    try:
        res = requests.post(API_URL, json=payload, timeout=REQUEST_TIMEOUT)
    except requests.Timeout:
        return None, "Storitev se ne odziva (timeout)."
    except requests.RequestException:
        return None, "Napaka pri povezavi s storitvijo."

    if res.status_code != 200:
        return None, f"Storitev je vrnila napako (HTTP {res.status_code})."
    try:
        data = res.json()
    except ValueError:
        return None, "Neveljaven odgovor storitve."
    if "Error code" in data:
        return None, f"Napaka API: {data['Error code']}"
    return data.get("List", {}), None


# --- Statični frontend -----------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# --- JSON API --------------------------------------------------------------

@app.route("/api/me")
def api_me():
    user = session.get("user")
    if not user:
        return jsonify({"error": "Potrebna je prijava."}), 401
    return jsonify({"user": user, "default_limit": DEFAULT_LIMIT})


@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute")
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    stored = USERS.get(username)
    if stored and check_password_hash(stored, password):
        session["user"] = username
        audit("login-ok", user_attempt=username)
        return jsonify({"user": username, "default_limit": DEFAULT_LIMIT})
    audit("login-fail", user_attempt=username)
    return jsonify({"error": "Napačno uporabniško ime ali geslo."}), 401


@app.route("/api/logout", methods=["POST"])
def api_logout():
    audit("logout")
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/search", methods=["POST"])
@api_login_required
@limiter.limit("20 per minute")
def api_search():
    data = request.get_json(silent=True) or {}
    query = (data.get("query") or "").strip()
    limit = clamp_limit(data.get("limit", DEFAULT_LIMIT))
    if not query:
        return jsonify({"error": "Vnesite iskalni pojem."}), 400

    results, error = query_leakosint(query, limit, DEFAULT_LANG)
    if error:
        audit("search-error", query=query, limit=limit, detail=error)
        return jsonify({"error": error}), 502
    db_count = len([k for k in results.keys() if k != "No results found"])
    audit("search-ok", query=query, limit=limit, databases=db_count)
    return jsonify({"query": query, "results": results})


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Preveč poizvedb. Počakajte trenutek."}), 429


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
