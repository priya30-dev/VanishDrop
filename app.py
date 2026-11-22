"""
VanishDrop: share private files with self-destructing, end-to-end encrypted links,
send files to nearby devices over your own Wi-Fi, and collect documents securely.

Run on your laptop:
    python app.py                        -> http://localhost:5000
    python app.py --https                -> lets phones on the same Wi-Fi open your links
    python app.py --name Priya --port 5001 --udp 50506 --tcp 50606 --data data-priya
                                         -> a second device on the same laptop, for testing
"""
import argparse
import hashlib
import hmac
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request, send_file, Response

from vd.db import DB
from vd.discovery import Discovery
from vd.identity import Identity, load_public
from vd.monitor import MON, Sniffer
from vd.transfer import CHAT_MAX_CHARS, CHAT_TTLS, LAN_MAX_BYTES, Node
from vd.util import b64d, lan_ip, safe_filename, wipe_file

LINK_MAX_BYTES = 200 * 1024 * 1024
NOTE_MAX_BYTES = 64 * 1024
UPLOAD_MAX_BYTES = 100 * 1024 * 1024
STORAGE_CAP_BYTES = 5 * 1024 * 1024 * 1024
LINK_EXPIRY = {600, 3600, 86400, 604800}
LINK_DOWNLOADS = {1, 3, 5, 10}
MAX_FAILURES = 5
REQUEST_EXPIRY = {86400, 259200, 604800}
REQUEST_MAX = {10, 30, 60, 100}
REQUEST_KEEP_AFTER_CLOSE = 7 * 86400
ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,40}$")
B64_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class State:
    pass


S = State()
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = LAN_MAX_BYTES + 16 * 1024 * 1024


# ================================================================ security ===
PROXY_HEADERS = ("X-Forwarded-For", "X-Forwarded-Host", "Forwarded", "X-Real-IP", "Cf-Connecting-Ip", "Cf-Ray")


def is_owner():
    """Only the person sitting at the computer running VanishDrop is the owner.

    A tunnel (Cloudflare, ngrok) also connects from 127.0.0.1, so anything that came
    through a proxy, or that uses the public address, is always a visitor.
    """
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return False
    if any(request.headers.get(h) for h in PROXY_HEADERS):
        return False
    if S.public_host and request.host.rsplit(":", 1)[0].strip("[]").lower() == S.public_host:
        return False
    return True


def owner_only(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not is_owner():
            if request.path.startswith("/api/"):
                return jsonify(error="Only the computer running VanishDrop can do this."), 403
            return render_template("visitor.html", page="visitor", owner_name=S.name()), 403
        return view(*args, **kwargs)
    return wrapper


@app.before_request
def guard():
    # DNS-rebinding defence: only answer to names we expect.
    host = request.host.rsplit(":", 1)[0].strip("[]").lower()
    if host not in S.allowed_hosts():
        return Response("Unknown host name.", 400)
    # CSRF defence: state-changing API calls need our custom header (other sites can't set it)
    # and, when the browser sends one, an Origin that matches this server.
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.path.startswith("/api/"):
        if request.headers.get("X-VD") != "1":
            return jsonify(error="Missing request header."), 400
        origin = request.headers.get("Origin")
        # Compare host:port only: behind an https tunnel the app itself sees plain http.
        if origin and urlparse(origin).netloc.lower() != request.host.lower():
            return jsonify(error="Cross-site request blocked."), 403


@app.context_processor
def inject_owner():
    return {"owner": is_owner()}


QUIET_PATHS = ("/static/", "/api/monitor", "/api/events", "/api/nearby/state", "/api/chat/state", "/favicon")


@app.after_request
def log_http(resp):
    if not request.path.startswith(QUIET_PATHS):
        secure = request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"
        peer = request.headers.get("Cf-Connecting-Ip") or request.remote_addr or ""
        body_note = ""
        if request.path.startswith(("/api/links", "/api/requests")) and ("/blob" in request.path or request.method == "POST"):
            body_note = "body is AES-256 ciphertext"
        path = request.path if len(request.path) <= 48 else request.path[:45] + "…"
        MON.log("http", "in", f"{request.method} {path}", peer, request.content_length or 0, encrypted=secure,
                note=body_note or ("HTTPS" if secure else "plain HTTP"))
        size = resp.content_length if resp.content_length is not None else 0
        MON.log("http", "out", f"{resp.status_code} {path}", peer, size, encrypted=secure, note=body_note)
    return resp


@app.after_request
def headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def err(message, code=400):
    return jsonify(error=message), code


def now():
    return time.time()


def storage_used():
    total = 0
    for folder in (S.links_dir, S.uploads_dir):
        for name in os.listdir(folder):
            try:
                total += os.path.getsize(os.path.join(folder, name))
            except OSError:
                pass
    return total


def save_upload(file_storage, dest, limit):
    """Stream an upload to disk and enforce the size limit while writing."""
    written = 0
    with open(dest, "wb") as out:
        while True:
            block = file_storage.stream.read(1024 * 1024)
            if not block:
                break
            written += len(block)
            if written > limit:
                out.close()
                wipe_file(dest)
                return None
            out.write(block)
    return written


def b64_field(value, max_len, exact_bytes=None):
    if not isinstance(value, str) or not value or len(value) > max_len or not B64_RE.match(value):
        return None
    try:
        raw = b64d(value)
    except ValueError:
        return None
    if exact_bytes is not None and len(raw) != exact_bytes:
        return None
    return value


# =================================================================== pages ===
@app.get("/")
@owner_only
def page_share():
    return render_template("share.html", page="share", kind="file")


@app.get("/notes")
@owner_only
def page_notes():
    return render_template("share.html", page="notes", kind="note")


@app.get("/nearby")
@owner_only
def page_nearby():
    return render_template("nearby.html", page="nearby")


@app.get("/chat")
@owner_only
def page_chat():
    return render_template("chat.html", page="chat")


@app.get("/requests")
@owner_only
def page_requests():
    return render_template("requests.html", page="requests")


@app.get("/files")
@owner_only
def page_files():
    return render_template("files.html", page="files")


@app.get("/server-view")
@owner_only
def page_server_view():
    return render_template("server_view.html", page="server")


@app.get("/d/<link_id>")
def page_download(link_id):
    if not ID_RE.match(link_id):
        return render_template("download.html", page="download", link_id=""), 404
    return render_template("download.html", page="download", link_id=link_id)


@app.get("/r/<req_id>")
def page_request_upload(req_id):
    return render_template("request_upload.html", page="request", req_id=req_id if ID_RE.match(req_id) else "")


@app.get("/api/whoami")
def api_whoami():
    if S.public_url:
        return jsonify(owner=is_owner(), name=S.name(), node=S.identity.fp[:16],
                       lan_url=S.public_url, https=S.public_url.startswith("https://"), public=True)
    scheme = "https" if S.https else "http"
    return jsonify(owner=is_owner(), name=S.name(), node=S.identity.fp[:16],
                   lan_url=f"{scheme}://{lan_ip()}:{S.http_port}", https=S.https, public=False)


# =================================================================== links ===
def end_link(c, link_id, status):
    c.execute("UPDATE links SET status=?, ended_at=? WHERE id=? AND status='active'", (status, now(), link_id))
    wipe_file(os.path.join(S.links_dir, link_id + ".bin"))


def link_status(row):
    if row["status"] == "active" and row["expires"] < now():
        return "expired"
    return row["status"]


@app.post("/api/links")
@owner_only
def api_link_create():
    form = request.form
    kind = form.get("kind", "file")
    if kind not in ("file", "note"):
        return err("Unknown share type.")
    try:
        expires_in = int(form.get("expires_in", ""))
        max_downloads = int(form.get("max_downloads", ""))
    except ValueError:
        return err("Expiry and download limit must be numbers.")
    if expires_in not in LINK_EXPIRY or max_downloads not in LINK_DOWNLOADS:
        return err("Choose an expiry and a download limit from the list.")
    enc_meta = b64_field(form.get("enc_meta"), 8192)
    auth = b64_field(form.get("auth"), 64, exact_bytes=32)
    password = form.get("password") == "1"
    salt = b64_field(form.get("salt"), 64, exact_bytes=16) if password else None
    if not enc_meta or not auth or (password and not salt):
        return err("The upload is missing its encrypted details. Reload the page and try again.")
    blob = request.files.get("blob")
    if blob is None:
        return err("No file was received.")
    limit = NOTE_MAX_BYTES if kind == "note" else LINK_MAX_BYTES
    if storage_used() + (request.content_length or 0) > STORAGE_CAP_BYTES:
        return err("This computer's VanishDrop storage is full. Destroy some old links first.", 507)

    link_id = secrets.token_urlsafe(12)
    path = os.path.join(S.links_dir, link_id + ".bin")
    size = save_upload(blob, path, limit + 28)
    if size is None:
        return err("That note is too long." if kind == "note" else "That file is over 200 MB.", 413)
    if size < 29:
        wipe_file(path)
        return err("That file is empty.")
    owner_token = secrets.token_urlsafe(24)
    auth_hash = hashlib.sha256(b64d(auth)).hexdigest()
    with S.db.conn() as c:
        c.execute("""INSERT INTO links (id, kind, owner_token, auth_hash, enc_meta, size, created, expires,
                     max_downloads, password, salt) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                  (link_id, kind, owner_token, auth_hash, enc_meta, size, now(), now() + expires_in,
                   max_downloads, int(password), salt))
    return jsonify(id=link_id, owner_token=owner_token, expires=now() + expires_in)


def _get_link(link_id):
    if not ID_RE.match(link_id):
        return None
    with S.db.conn() as c:
        row = c.execute("SELECT * FROM links WHERE id=?", (link_id,)).fetchone()
    return dict(row) if row else None


def _link_public(row):
    return {"status": "active", "kind": row["kind"], "size": row["size"], "expires": row["expires"],
            "downloads_left": row["max_downloads"] - row["downloads"], "password": bool(row["password"]),
            "salt": row["salt"], "attempts_left": MAX_FAILURES - row["failures"]}


@app.get("/api/links/<link_id>")
def api_link_info(link_id):
    row = _get_link(link_id)
    if row is None:
        return jsonify(status="missing"), 404
    status = link_status(row)
    if status != "active":
        return jsonify(status=status), 410
    return jsonify(_link_public(row))


def _check_auth(link_id):
    """Returns (row, error_response). Wrong tokens count toward the lockout."""
    token = request.headers.get("X-VD-Auth", "")
    try:
        raw = b64d(token) if token else b""
    except ValueError:
        raw = b""
    with S.db.lock:
        row = _get_link(link_id)
        if row is None:
            return None, (jsonify(status="missing"), 404)
        if link_status(row) != "active":
            return None, (jsonify(status=link_status(row)), 410)
        given = hashlib.sha256(raw).hexdigest() if len(raw) == 32 else ""
        if given and hmac.compare_digest(given, row["auth_hash"]):
            return row, None
        failures = row["failures"] + 1
        with S.db.conn() as c:
            c.execute("UPDATE links SET failures=? WHERE id=?", (failures, link_id))
            if failures >= MAX_FAILURES:
                end_link(c, link_id, "locked")
        if failures >= MAX_FAILURES:
            S.db.event("link_locked", link_id, "A link was locked after 5 wrong passwords, and its file was wiped.")
            return None, (jsonify(status="locked", error="Too many wrong attempts. The file was destroyed."), 410)
        left = MAX_FAILURES - failures
        return None, (jsonify(error=f"Wrong password. {left} {'try' if left == 1 else 'tries'} left before the file is destroyed.",
                              attempts_left=left), 403)


@app.post("/api/links/<link_id>/open")
def api_link_open(link_id):
    row, error = _check_auth(link_id)
    if error:
        return error
    return jsonify(_link_public(row) | {"enc_meta": row["enc_meta"]})


@app.get("/api/links/<link_id>/blob")
def api_link_blob(link_id):
    with S.db.lock:
        row, error = _check_auth(link_id)
        if error:
            return error
        path = os.path.join(S.links_dir, link_id + ".bin")
        with open(path, "rb") as fh:
            data = fh.read()
        downloads = row["downloads"] + 1
        last = downloads >= row["max_downloads"]
        with S.db.conn() as c:
            c.execute("UPDATE links SET downloads=? WHERE id=?", (downloads, link_id))
            if last:
                end_link(c, link_id, "downloaded")
    what = "note was read" if row["kind"] == "note" else "file was downloaded"
    S.db.event("link_download", link_id,
               f"A {what}" + (" and destroyed." if last else f". {row['max_downloads'] - downloads} left."))
    resp = Response(data, mimetype="application/octet-stream")
    resp.headers["X-Downloads-Left"] = str(row["max_downloads"] - downloads)
    return resp


@app.post("/api/links/<link_id>/destroy")
@owner_only
def api_link_destroy(link_id):
    token = (request.get_json(silent=True) or {}).get("owner_token", "")
    row = _get_link(link_id)
    if row is None or not isinstance(token, str) or not hmac.compare_digest(row["owner_token"], token):
        return err("Only the person who shared this can destroy it.", 403)
    with S.db.conn() as c:
        end_link(c, link_id, "revoked")
    return jsonify(status="revoked")


@app.post("/api/links/status")
@owner_only
def api_link_status():
    items = (request.get_json(silent=True) or {}).get("items", [])
    out = {}
    for item in items[:300] if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        row = _get_link(str(item.get("id", "")))
        token = item.get("token", "")
        if row is None or not isinstance(token, str) or not hmac.compare_digest(row["owner_token"], token):
            out[str(item.get("id"))] = {"status": "missing"}
            continue
        out[row["id"]] = {"status": link_status(row), "downloads": row["downloads"],
                          "max_downloads": row["max_downloads"], "expires": row["expires"],
                          "ended_at": row["ended_at"], "failures": row["failures"]}
    return jsonify(out)


# ========================================================= upload requests ===
@app.post("/api/requests")
@owner_only
def api_request_create():
    body = request.get_json(silent=True) or {}
    title = body.get("title")
    if not isinstance(title, str) or not 1 <= len(title.strip()) <= 80:
        return err("Give the request a title of up to 80 characters.")
    try:
        expires_in, max_uploads = int(body.get("expires_in")), int(body.get("max_uploads"))
    except (TypeError, ValueError):
        return err("Choose a deadline and an upload limit.")
    if expires_in not in REQUEST_EXPIRY or max_uploads not in REQUEST_MAX:
        return err("Choose a deadline and an upload limit from the list.")
    pub = b64_field(body.get("public_key"), 2048)
    try:
        load_public(b64d(pub or ""))
    except Exception:
        return err("The request's public key is invalid.")
    req_id, token = secrets.token_urlsafe(12), secrets.token_urlsafe(24)
    with S.db.conn() as c:
        c.execute("""INSERT INTO requests (id, owner_token, title, public_key, created, expires, max_uploads)
                     VALUES (?,?,?,?,?,?,?)""", (req_id, token, title.strip(), pub, now(), now() + expires_in, max_uploads))
    return jsonify(id=req_id, owner_token=token)


def _get_request(req_id):
    if not ID_RE.match(req_id):
        return None
    with S.db.conn() as c:
        row = c.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
    return dict(row) if row else None


def request_open(row):
    return row["status"] == "open" and row["expires"] > now() and row["received"] < row["max_uploads"]


@app.get("/api/requests/<req_id>")
def api_request_info(req_id):
    row = _get_request(req_id)
    if row is None:
        return jsonify(status="missing"), 404
    return jsonify(status="open" if request_open(row) else "closed", title=row["title"], owner_name=S.name(),
                   public_key=row["public_key"], expires=row["expires"],
                   remaining=max(0, row["max_uploads"] - row["received"]))


@app.post("/api/requests/<req_id>/upload")
def api_request_upload(req_id):
    enc_meta = b64_field(request.form.get("enc_meta"), 8192)
    wrapped = b64_field(request.form.get("wrapped_key"), 1024)
    blob = request.files.get("blob")
    if not enc_meta or not wrapped or blob is None:
        return err("The upload is missing its encrypted details. Reload the page and try again.")
    if storage_used() + (request.content_length or 0) > STORAGE_CAP_BYTES:
        return err("The receiver's storage is full. Ask them to download what they've received.", 507)
    with S.db.lock:
        row = _get_request(req_id)
        if row is None:
            return err("This request doesn't exist.", 404)
        if not request_open(row):
            return err("This request is closed. Ask the person who sent it for a new link.", 410)
        with S.db.conn() as c:
            c.execute("UPDATE requests SET received=received+1 WHERE id=?", (req_id,))
    up_id = secrets.token_urlsafe(12)
    path = os.path.join(S.uploads_dir, up_id + ".bin")
    try:
        size = save_upload(blob, path, UPLOAD_MAX_BYTES + 28)
    except Exception:
        size = -1  # the connection dropped mid-upload
    if size is None or size < 29:
        # Give the slot back: a failed upload must not count.
        wipe_file(path)
        with S.db.conn() as c:
            c.execute("UPDATE requests SET received=received-1 WHERE id=?", (req_id,))
        if size == -1:
            return err("The upload was interrupted. Try again.", 400)
        return err("Files must be between 1 byte and 100 MB.", 413)
    with S.db.conn() as c:
        c.execute("INSERT INTO uploads (id, request_id, enc_meta, wrapped_key, size, created) VALUES (?,?,?,?,?,?)",
                  (up_id, req_id, enc_meta, wrapped, size, now()))
    S.db.event("request_upload", req_id, f"Someone uploaded a file to “{row['title']}”.")
    return jsonify(ok=True)


def _owned_request(req_id):
    row = _get_request(req_id)
    token = request.headers.get("X-VD-Owner", "")
    if row is None or not token or not hmac.compare_digest(row["owner_token"], token):
        return None
    return row


@app.post("/api/requests/status")
@owner_only
def api_request_status():
    items = (request.get_json(silent=True) or {}).get("items", [])
    out = {}
    for item in items[:100] if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        row = _get_request(str(item.get("id", "")))
        token = item.get("token", "")
        if row is None or not isinstance(token, str) or not hmac.compare_digest(row["owner_token"], token):
            out[str(item.get("id"))] = {"status": "missing"}
            continue
        with S.db.conn() as c:
            ups = [dict(u) for u in c.execute(
                "SELECT id, enc_meta, wrapped_key, size, created FROM uploads WHERE request_id=? ORDER BY created",
                (row["id"],))]
        out[row["id"]] = {"status": "open" if request_open(row) else "closed", "title": row["title"],
                          "expires": row["expires"], "received": row["received"],
                          "max_uploads": row["max_uploads"], "uploads": ups}
    return jsonify(out)


@app.get("/api/requests/<req_id>/uploads/<up_id>/blob")
@owner_only
def api_request_blob(req_id, up_id):
    if _owned_request(req_id) is None or not ID_RE.match(up_id):
        return err("Not found.", 404)
    with S.db.conn() as c:
        up = c.execute("SELECT * FROM uploads WHERE id=? AND request_id=?", (up_id, req_id)).fetchone()
    if up is None:
        return err("Not found.", 404)
    return send_file(os.path.join(S.uploads_dir, up_id + ".bin"), mimetype="application/octet-stream")


@app.post("/api/requests/<req_id>/uploads/<up_id>/delete")
@owner_only
def api_request_upload_delete(req_id, up_id):
    if _owned_request(req_id) is None or not ID_RE.match(up_id):
        return err("Not found.", 404)
    with S.db.conn() as c:
        c.execute("DELETE FROM uploads WHERE id=? AND request_id=?", (up_id, req_id))
    wipe_file(os.path.join(S.uploads_dir, up_id + ".bin"))
    return jsonify(ok=True)


@app.post("/api/requests/<req_id>/close")
@owner_only
def api_request_close(req_id):
    if _owned_request(req_id) is None:
        return err("Not found.", 404)
    close_request(req_id, wipe=True)
    return jsonify(ok=True)


def close_request(req_id, wipe):
    with S.db.conn() as c:
        c.execute("UPDATE requests SET status='closed', ended_at=COALESCE(ended_at, ?) WHERE id=?", (now(), req_id))
        if wipe:
            ids = [r["id"] for r in c.execute("SELECT id FROM uploads WHERE request_id=?", (req_id,))]
            c.execute("DELETE FROM uploads WHERE request_id=?", (req_id,))
    if wipe:
        for up_id in ids:
            wipe_file(os.path.join(S.uploads_dir, up_id + ".bin"))


# ================================================================== nearby ===
@app.get("/api/nearby/state")
@owner_only
def api_nearby_state():
    friends = {f["fp"]: f for f in S.node.friends()}
    peers = [{"fp": p["fp"], "name": p["name"], "ip": p["ip"], "friend": p["fp"] in friends}
             for p in S.discovery.list_peers()]
    with S.db.conn() as c:
        inbox = [dict(r) for r in c.execute(
            "SELECT id, name, size, from_name, friend, plain, received FROM inbox ORDER BY received DESC LIMIT 100")]
    snap = S.node.snapshot()
    return jsonify(me={"name": S.name(), "fp": S.identity.fp, "ip": lan_ip(), "tcp": S.node.tcp_port,
                       "udp": S.discovery.udp_port},
                   settings={"auto_accept": S.node.setting_bool("auto_accept", True),
                             "allow_plain": S.node.setting_bool("allow_plain", False)},
                   peers=sorted(peers, key=lambda p: (not p["friend"], p["name"].lower())),
                   friends=list(friends.values()), inbox=inbox, **snap)


@app.post("/api/nearby/settings")
@owner_only
def api_nearby_settings():
    body = request.get_json(silent=True) or {}
    if "name" in body:
        name = body["name"]
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 40:
            return err("Use a device name of 1 to 40 characters.")
        S.db.set_setting("name", name.strip())
    for key in ("auto_accept", "allow_plain"):
        if key in body:
            S.db.set_setting(key, "1" if body[key] else "0")
    return jsonify(ok=True)


@app.post("/api/nearby/pair")
@owner_only
def api_nearby_pair():
    fp = (request.get_json(silent=True) or {}).get("fp")
    if not isinstance(fp, str) or not S.discovery.peer(fp):
        return err("That device isn't nearby any more.")
    return jsonify(id=S.node.pair(fp))


@app.post("/api/nearby/send")
@owner_only
def api_nearby_send():
    fp = request.form.get("fp", "")
    plain = request.form.get("plain") == "1"
    upload = request.files.get("file")
    if not S.discovery.peer(fp):
        return err("That device isn't nearby any more.")
    if upload is None or not upload.filename:
        return err("Choose a file to send.")
    staged = os.path.join(S.node.outbox_dir, secrets.token_hex(12))
    size = save_upload(upload, staged, LAN_MAX_BYTES)
    if size is None:
        return err("Files sent to nearby devices can be up to 4 GB.", 413)
    if size == 0:
        wipe_file(staged)
        return err("That file is empty.")
    return jsonify(id=S.node.send_file(fp, staged, safe_filename(upload.filename), plain))


@app.post("/api/nearby/jobs/<jid>/<action>")
@owner_only
def api_nearby_job(jid, action):
    ok = S.node.retry(jid) if action == "retry" else S.node.cancel(jid) if action == "cancel" else False
    return jsonify(ok=ok) if ok else err("That transfer can't do that right now.")


@app.post("/api/nearby/pending/<pid>")
@owner_only
def api_nearby_decide(pid):
    accept = bool((request.get_json(silent=True) or {}).get("accept"))
    return jsonify(ok=True) if S.node.decide(pid, accept) else err("That request has already ended.", 410)


def _inbox_row(iid):
    with S.db.conn() as c:
        row = c.execute("SELECT * FROM inbox WHERE id=?", (iid,)).fetchone()
    return dict(row) if row else None


@app.get("/api/nearby/inbox/<iid>")
@owner_only
def api_inbox_file(iid):
    row = _inbox_row(iid)
    if row is None or not os.path.exists(row["path"]):
        return err("That file is no longer in your inbox.", 404)
    return send_file(row["path"], as_attachment=True, download_name=row["name"])


@app.post("/api/nearby/inbox/<iid>/delete")
@owner_only
def api_inbox_delete(iid):
    row = _inbox_row(iid)
    if row is None:
        return err("Not found.", 404)
    wipe_file(row["path"])
    with S.db.conn() as c:
        c.execute("DELETE FROM inbox WHERE id=?", (iid,))
    return jsonify(ok=True)


@app.post("/api/nearby/friends/remove")
@owner_only
def api_friend_remove():
    fp = (request.get_json(silent=True) or {}).get("fp")
    if isinstance(fp, str):
        S.node.remove_friend(fp)
    return jsonify(ok=True)


# ==================================================================== chat ===
@app.get("/api/chat/state")
@owner_only
def api_chat_state():
    peer = request.args.get("peer", "")
    online = {p["fp"] for p in S.discovery.list_peers()}
    with S.db.conn() as c:
        if peer:
            c.execute("UPDATE chats SET read=1 WHERE peer_fp=? AND direction='in'", (peer,))
        unread = {r["peer_fp"]: r["n"] for r in c.execute(
            "SELECT peer_fp, COUNT(*) n FROM chats WHERE direction='in' AND read=0 GROUP BY peer_fp")}
        last = {r["peer_fp"]: r["at"] for r in c.execute("SELECT peer_fp, MAX(at) at FROM chats GROUP BY peer_fp")}
        msgs = [dict(r) for r in c.execute(
            "SELECT mid, direction, text, at, ttl, expires, status, error FROM chats WHERE peer_fp=? ORDER BY at",
            (peer,))] if peer else []
    friends = [{"fp": f["fp"], "name": f["name"], "online": f["fp"] in online,
                "unread": unread.get(f["fp"], 0), "last": last.get(f["fp"])} for f in S.node.friends()]
    friends.sort(key=lambda f: (-(f["last"] or 0), f["name"].lower()))
    return jsonify(friends=friends, messages=msgs, now=now())


@app.post("/api/chat/send")
@owner_only
def api_chat_send():
    body = request.get_json(silent=True) or {}
    fp, text = body.get("fp"), body.get("text")
    try:
        ttl = int(body.get("ttl", 3600))
    except (TypeError, ValueError):
        return err("Choose how long messages last.")
    if ttl not in CHAT_TTLS:
        return err("Choose how long messages last from the list.")
    if not isinstance(text, str) or not text.strip():
        return err("Write a message first.")
    if len(text) > CHAT_MAX_CHARS:
        return err("Messages can be up to 4,000 characters.")
    if not isinstance(fp, str) or not S.node.friend(fp):
        return err("You can only chat with friends. Pair on the Nearby page first.")
    return jsonify(mid=S.node.send_chat(fp, text.strip(), ttl))


@app.post("/api/chat/retry/<mid>")
@owner_only
def api_chat_retry(mid):
    return jsonify(ok=True) if S.node.retry_chat(mid) else err("That message can't be retried.")


@app.post("/api/chat/clear")
@owner_only
def api_chat_clear():
    fp = (request.get_json(silent=True) or {}).get("fp")
    with S.db.conn() as c:
        c.execute("DELETE FROM chats WHERE peer_fp=?", (fp,))
    return jsonify(ok=True)


# ========================================================= network check ===
# Module 1: run the standard networking commands safely (fixed programs, no shell,
# validated targets) and show their output with an explanation.
WINDOWS = os.name == "nt"
TARGET_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")
netcheck_lock = threading.Lock()


def _which(*names):
    for n in names:
        if shutil.which(n):
            return n
    return None


def netcheck_command(tool, target):
    if tool == "ipconfig":
        return ["ipconfig", "/all"] if WINDOWS else (["ip", "addr"] if _which("ip") else ["ifconfig"])
    if tool == "route":
        return ["route", "print", "-4"] if WINDOWS else (["ip", "route"] if _which("ip") else ["netstat", "-rn"])
    if tool == "arp":
        return ["arp", "-a"] if WINDOWS else (["ip", "neigh"] if _which("ip") else ["arp", "-a"])
    if tool == "netstat":
        if WINDOWS:
            return ["netstat", "-ano"]
        return ["ss", "-tulpn"] if _which("ss") else ["netstat", "-tulpn"]
    if tool in ("ping", "traceroute", "nslookup"):
        if not target or not TARGET_RE.match(target):
            raise ValueError("Enter a host name or IP address, like google.com or 192.168.1.1.")
        if tool == "ping":
            return ["ping", "-n", "4", target] if WINDOWS else ["ping", "-c", "4", "-W", "2", target]
        if tool == "traceroute":
            if WINDOWS:
                return ["tracert", "-d", "-h", "15", "-w", "1000", target]
            prog = _which("traceroute", "tracepath")
            if prog == "traceroute":
                return ["traceroute", "-n", "-m", "15", "-w", "1", target]
            if prog == "tracepath":
                return ["tracepath", "-n", "-m", "15", target]
            raise ValueError("traceroute isn't installed on this computer.")
        return ["nslookup", target]
    raise ValueError("Unknown tool.")


def default_gateway():
    try:
        if WINDOWS:
            out = subprocess.run(["ipconfig"], capture_output=True, text=True, encoding="oem", errors="replace", timeout=10).stdout
            m = re.search(r"Default Gateway[ .]*: *([0-9.]+)", out)
        else:
            out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=10).stdout
            m = re.search(r"default via ([0-9.]+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.SubprocessError):
        return None


@app.get("/monitor")
@owner_only
def page_monitor():
    return render_template("monitor.html", page="monitor")


@app.get("/api/monitor")
@owner_only
def api_monitor():
    try:
        after = int(request.args.get("after", "0"))
    except ValueError:
        after = 0
    snap = MON.snapshot(after=after)
    snap["capture"] = {"available": Sniffer.available(), "running": S.sniffer.running, "error": S.sniffer.error}
    snap["ports"] = {"web": S.http_port, "udp": S.discovery.udp_port, "tcp": S.node.tcp_port}
    return jsonify(snap)


@app.post("/api/monitor/clear")
@owner_only
def api_monitor_clear():
    MON.clear()
    return jsonify(ok=True)


@app.post("/api/monitor/capture")
@owner_only
def api_monitor_capture():
    on = bool((request.get_json(silent=True) or {}).get("on"))
    if on:
        ok = S.sniffer.start()
        if not ok:
            return err(S.sniffer.error or "Packet capture couldn't start.")
    else:
        S.sniffer.stop()
    return jsonify(running=S.sniffer.running)


@app.get("/network")
@owner_only
def page_network():
    return render_template("network.html", page="network")


@app.get("/api/netcheck/info")
@owner_only
def api_netcheck_info():
    return jsonify(windows=WINDOWS, ip=lan_ip(), gateway=default_gateway(),
                   ports={"web": S.http_port, "udp": S.discovery.udp_port, "tcp": S.node.tcp_port},
                   peers=[{"name": p["name"], "ip": p["ip"]} for p in S.discovery.list_peers()])


@app.post("/api/netcheck")
@owner_only
def api_netcheck():
    body = request.get_json(silent=True) or {}
    tool, target = body.get("tool"), (body.get("target") or "").strip()
    try:
        cmd = netcheck_command(tool, target)
    except ValueError as exc:
        return err(str(exc))
    if not netcheck_lock.acquire(blocking=False):
        return err("Another command is still running. Wait for it to finish.", 429)
    try:
        started = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                                  encoding="oem" if WINDOWS else "utf-8", errors="replace")
            out, code = (proc.stdout or "") + (proc.stderr or ""), proc.returncode
        except FileNotFoundError:
            return err(f"The {cmd[0]} command isn't available on this computer.")
        except subprocess.TimeoutExpired as exc:
            out, code = (exc.stdout or "") if isinstance(exc.stdout, str) else "", "timeout"
            out += "\n[Stopped after 60 seconds]"
        if tool == "netstat":
            ports = sorted({str(S.http_port), str(S.discovery.udp_port), str(S.node.tcp_port)})
            pat = re.compile(r"[:.](%s)\b" % "|".join(ports))
            lines = out.splitlines()
            header = [l for l in lines[:6] if re.search(r"Proto|Netid", l)][:1]
            keep = [l for l in lines if pat.search(l)]
            out = (f"Showing only VanishDrop's ports ({', '.join(ports)}).\n\n" + "\n".join(header + keep)) if keep else out
        return jsonify(command=" ".join(cmd), output=out[-60000:], code=code, seconds=round(time.time() - started, 1))
    finally:
        netcheck_lock.release()


# ========================================================== events & server ===
@app.get("/api/events")
@owner_only
def api_events():
    try:
        after = int(request.args.get("after", "-1"))
    except ValueError:
        after = -1
    with S.db.conn() as c:
        latest = c.execute("SELECT COALESCE(MAX(n), 0) FROM events").fetchone()[0]
        if after < 0:
            rows = c.execute("SELECT * FROM events ORDER BY n DESC LIMIT 40").fetchall()
        else:
            rows = c.execute("SELECT * FROM events WHERE n>? ORDER BY n LIMIT 50", (after,)).fetchall()
    return jsonify(latest=latest, events=[dict(r) for r in rows])


@app.get("/api/server-view")
@owner_only
def api_server_view():
    def head(path):
        try:
            with open(path, "rb") as fh:
                return fh.read(160).hex()
        except OSError:
            return ""
    with S.db.conn() as c:
        links = [dict(r) for r in c.execute(
            "SELECT id, kind, size, created, enc_meta, password FROM links WHERE status='active' ORDER BY created DESC LIMIT 20")]
        ups = [dict(r) for r in c.execute(
            "SELECT id, size, created, enc_meta, wrapped_key FROM uploads ORDER BY created DESC LIMIT 20")]
    for row in links:
        row["head"] = head(os.path.join(S.links_dir, row["id"] + ".bin"))
    for row in ups:
        row["head"] = head(os.path.join(S.uploads_dir, row["id"] + ".bin"))
    return jsonify(links=links, uploads=ups)


@app.errorhandler(413)
def too_large(_):
    return err("That file is too large.", 413)


# ================================================================== cleanup ===
def cleanup_loop():
    while True:
        try:
            t = now()
            with S.db.conn() as c:
                for row in c.execute("SELECT id FROM links WHERE status='active' AND expires<?", (t,)).fetchall():
                    end_link(c, row["id"], "expired")
                expired_reqs = c.execute("SELECT id FROM requests WHERE status='open' AND expires<?", (t,)).fetchall()
                old_reqs = c.execute("SELECT id FROM requests WHERE status='closed' AND ended_at<?",
                                     (t - REQUEST_KEEP_AFTER_CLOSE,)).fetchall()
                c.execute("DELETE FROM chats WHERE expires IS NOT NULL AND expires<?", (t,))
            for row in expired_reqs:
                close_request(row["id"], wipe=False)
            for row in old_reqs:
                close_request(row["id"], wipe=True)
            for name in os.listdir(S.node.partial_dir):
                p = os.path.join(S.node.partial_dir, name)
                if t - os.path.getmtime(p) > 7 * 86400:
                    wipe_file(p)
        except Exception as exc:
            print("cleanup error:", exc)
        time.sleep(30)


# ===================================================================== main ===
def create_app(data_dir="data", name=None, http_port=5000, udp_port=50505, tcp_port=50605, https=False,
               extra_hosts=(), public_url=None):
    os.makedirs(data_dir, exist_ok=True)
    S.data_dir = data_dir
    S.links_dir = os.path.join(data_dir, "links")
    S.uploads_dir = os.path.join(data_dir, "uploads")
    os.makedirs(S.links_dir, exist_ok=True)
    os.makedirs(S.uploads_dir, exist_ok=True)
    S.db = DB(os.path.join(data_dir, "vanishdrop.db"))
    S.identity = Identity(os.path.join(data_dir, "device_key.pem"))
    if name:
        S.db.set_setting("name", name[:40])
    default_name = socket.gethostname()[:40] or "My laptop"
    S.name = lambda: S.db.setting("name", default_name)
    S.http_port, S.https = http_port, https
    S.public_url = public_url.rstrip("/") if public_url else None
    S.public_host = urlparse(S.public_url).hostname.lower() if S.public_url else None
    public_hosts = {S.public_host} if S.public_host else set()
    S.allowed_hosts = lambda: {"localhost", "127.0.0.1", "::1", lan_ip(), *extra_hosts, *public_hosts}
    S.node = Node(S.identity, S.db, data_dir, tcp_port, lambda: S.discovery, S.name)
    S.discovery = Discovery(S.identity, udp_port, tcp_port, http_port, S.name, S.node.on_alert, lan_ip)
    S.sniffer = Sniffer(lambda: (S.http_port, S.discovery.udp_port, S.node.tcp_port))
    S.node.start()
    S.discovery.start()
    threading.Thread(target=cleanup_loop, daemon=True).start()
    return app


def main():
    ap = argparse.ArgumentParser(description="VanishDrop")
    ap.add_argument("--port", type=int, default=5000, help="web port (default 5000)")
    ap.add_argument("--udp", type=int, default=50505, help="discovery port, 50505 to 50510")
    ap.add_argument("--tcp", type=int, default=50605, help="device-to-device transfer port")
    ap.add_argument("--data", default="data", help="folder for this device's files and keys")
    ap.add_argument("--name", help="this device's name, shown to nearby devices")
    ap.add_argument("--https", action="store_true", help="serve HTTPS so phones on your Wi-Fi can open links")
    ap.add_argument("--host-name", action="append", default=[], help="extra host name to allow")
    ap.add_argument("--public-url", help="public https address from a tunnel, e.g. https://abc.trycloudflare.com")
    args = ap.parse_args()
    if args.public_url:
        parsed = urlparse(args.public_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            ap.error("--public-url must look like https://something.trycloudflare.com")
    if not 50505 <= args.udp <= 50510:
        ap.error("--udp must be between 50505 and 50510 so devices can find each other")
    create_app(args.data, args.name, args.port, args.udp, args.tcp, args.https, args.host_name, args.public_url)
    scheme = "https" if args.https else "http"
    print(f"\n  VanishDrop is running as “{S.name()}”")
    print(f"  Open on this laptop:   {scheme}://localhost:{args.port}")
    if args.public_url:
        print(f"  Links work for anyone at {S.public_url}  (through your tunnel)")
    else:
        print(f"  Links work for others at {scheme}://{lan_ip()}:{args.port}")
        if not args.https:
            print("  Phones need HTTPS to decrypt: restart with  py app.py --https")
    print(f"  Nearby: UDP {args.udp}, TCP {args.tcp}\n")
    app.run(host="0.0.0.0", port=args.port, threaded=True, debug=False,
            ssl_context="adhoc" if args.https else None)


if __name__ == "__main__":
    main()
