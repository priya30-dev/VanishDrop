/* Shared helpers: encryption (Web Crypto), API calls, formatting, alerts. */
(function () {
  "use strict";
  const enc = new TextEncoder(), dec = new TextDecoder();

  // ---------- base64url ----------
  function toB64(bytes) {
    const arr = new Uint8Array(bytes); let s = "";
    for (let i = 0; i < arr.length; i += 0x8000) s += String.fromCharCode.apply(null, arr.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function fromB64(str) {
    if (!/^[A-Za-z0-9_-]*$/.test(str)) throw new Error("bad base64");
    const s = str.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(s + "===".slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ---------- crypto ----------
  const canCrypto = () => !!(window.isSecureContext && window.crypto && crypto.subtle);
  const PBKDF2_ROUNDS = 600000;

  // One secret -> two independent keys: one encrypts, one proves you hold the link.
  async function keysFromSecret(secret) {
    const base = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey", "deriveBits"]);
    const salt = new Uint8Array(32);
    const encKey = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: enc.encode("vanishdrop enc v1") },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const auth = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: enc.encode("vanishdrop auth v1") }, base, 256);
    return { encKey, auth: toB64(auth) };
  }
  async function secretFromPassword(password, saltB64) {
    const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: fromB64(saltB64), iterations: PBKDF2_ROUNDS, hash: "SHA-256" }, base, 256));
  }
  // Layout: 12-byte IV, then ciphertext with its 16-byte GCM tag.
  async function encrypt(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data));
    const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
    return out;
  }
  async function decrypt(key, data) {
    const b = new Uint8Array(data);
    return crypto.subtle.decrypt({ name: "AES-GCM", iv: b.subarray(0, 12) }, key, b.subarray(12));
  }
  const encryptText = async (key, text) => toB64(await encrypt(key, enc.encode(text)));
  const decryptText = async (key, b64) => dec.decode(await decrypt(key, fromB64(b64)));

  // RSA-OAEP for upload requests: the private key never leaves this browser.
  const RSA = { name: "RSA-OAEP", hash: "SHA-256" };
  async function newRequestKeys() {
    return crypto.subtle.generateKey({ ...RSA, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
      false, ["encrypt", "decrypt"]);
  }
  async function exportPublic(key) { return toB64(await crypto.subtle.exportKey("spki", key)); }
  async function importPublic(b64) { return crypto.subtle.importKey("spki", fromB64(b64), RSA, false, ["encrypt"]); }
  async function sealForRequest(publicKey, data, metaText) {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const aes = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
    const wrapped = toB64(await crypto.subtle.encrypt(RSA, publicKey, raw));
    raw.fill(0);
    return { wrapped, blob: await encrypt(aes, data), meta: await encryptText(aes, metaText) };
  }
  async function openFromRequest(privateKey, wrappedB64) {
    const raw = new Uint8Array(await crypto.subtle.decrypt(RSA, privateKey, fromB64(wrappedB64)));
    const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
    raw.fill(0);
    return key;
  }
  async function checkCode(publicB64) {
    const h = new Uint8Array(await crypto.subtle.digest("SHA-256", fromB64(publicB64)));
    const hex = Array.from(h.slice(0, 6), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
    return hex.match(/.{4}/g).join("-");
  }

  // ---------- IndexedDB (stores non-extractable private keys) ----------
  function idb() {
    return new Promise((res, rej) => {
      const r = indexedDB.open("vanishdrop", 1);
      r.onupgradeneeded = () => r.result.createObjectStore("keys");
      r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
    });
  }
  async function idbOp(mode, fn) {
    const db = await idb();
    return new Promise((res, rej) => {
      const tx = db.transaction("keys", mode); const req = fn(tx.objectStore("keys"));
      tx.oncomplete = () => res(req && req.result); tx.onerror = () => rej(tx.error);
    });
  }
  const keyStore = {
    put: (k, v) => idbOp("readwrite", (s) => s.put(v, k)),
    get: (k) => idbOp("readonly", (s) => s.get(k)),
    del: (k) => idbOp("readwrite", (s) => s.delete(k)),
  };

  // ---------- API ----------
  async function api(path, opts = {}) {
    const headers = Object.assign({ "X-VD": "1" }, opts.headers || {});
    let body = opts.body;
    if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(opts.json); }
    const res = await fetch(path, { method: opts.method || (body ? "POST" : "GET"), headers, body, cache: "no-store" });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { const e = new Error(data.error || `Request failed (${res.status})`); e.status = res.status; e.data = data; throw e; }
    return data;
  }
  function upload(path, form, onProgress, headers = {}) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", path);
      xhr.setRequestHeader("X-VD", "1");
      Object.entries(headers).forEach(([k, v]) => xhr.setRequestHeader(k, v));
      xhr.upload.onprogress = (e) => { if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total); };
      xhr.onload = () => {
        let body = {}; try { body = JSON.parse(xhr.responseText); } catch (e) { /* not JSON */ }
        if (xhr.status >= 200 && xhr.status < 300) resolve(body);
        else reject(new Error(body.error || `Upload failed (${xhr.status})`));
      };
      xhr.onerror = () => reject(new Error("Couldn't reach VanishDrop. Check it's still running."));
      xhr.send(form);
    });
  }
  async function download(path, total, onProgress, headers = {}) {
    const res = await fetch(path, { headers: Object.assign({ "X-VD": "1" }, headers), cache: "no-store" });
    if (!res.ok) { const data = await res.json().catch(() => ({})); const e = new Error(data.error || `Download failed (${res.status})`); e.status = res.status; e.data = data; throw e; }
    const reader = res.body.getReader(); const parts = []; let got = 0;
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      parts.push(value); got += value.length; if (onProgress && total) onProgress(Math.min(1, got / total));
    }
    const out = new Uint8Array(got); let off = 0; parts.forEach((p) => { out.set(p, off); off += p.length; });
    return { data: out, headers: res.headers };
  }
  function saveBlob(bytes, name, type) {
    const url = URL.createObjectURL(new Blob([bytes], { type: type || "application/octet-stream" }));
    const a = document.createElement("a"); a.href = url; a.download = name || "file";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  // ---------- formatting ----------
  function bytes(n) {
    if (n < 1024) return n + " B";
    const u = ["KB", "MB", "GB"]; let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(n < 10 ? 1 : 0) + " " + u[i];
  }
  function timeLeft(t) {
    let s = Math.max(0, Math.round(t - Date.now() / 1000));
    if (!s) return "now";
    const d = Math.floor(s / 86400); s %= 86400; const h = Math.floor(s / 3600); s %= 3600;
    const m = Math.floor(s / 60); s %= 60;
    if (d) return `${d}d ${h}h`; if (h) return `${h}h ${m}m`; if (m) return `${m}m ${String(s).padStart(2, "0")}s`;
    return `${s}s`;
  }
  function ago(t) {
    const s = Math.round(Date.now() / 1000 - t);
    if (s < 60) return "just now"; if (s < 3600) return Math.floor(s / 60) + " min ago";
    if (s < 86400) return Math.floor(s / 3600) + " h ago"; return Math.floor(s / 86400) + " d ago";
  }
  const ext = (name) => { const m = /\.([a-z0-9]{1,5})$/i.exec(name || ""); return m ? m[1].toUpperCase() : "FILE"; };
  function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function setProgress(prefix, text, frac) {
    const pct = Math.round(Math.max(0, Math.min(1, frac)) * 100);
    document.getElementById(prefix + "-text").textContent = text;
    document.getElementById(prefix + "-pct").textContent = pct + "%";
    document.getElementById(prefix + "-fill").style.width = pct + "%";
  }
  function qrDataUrl(text) {
    if (!window.qrcode) return "";
    const q = qrcode(0, "M"); q.addData(text); q.make();
    return q.createDataURL(4, 0);
  }
  async function copy(text, btn) {
    try { await navigator.clipboard.writeText(text); }
    catch (e) { const t = el("textarea"); t.value = text; document.body.appendChild(t); t.select(); document.execCommand("copy"); t.remove(); }
    if (btn) { const old = btn.textContent; btn.textContent = "Copied"; setTimeout(() => (btn.textContent = old), 1600); }
  }

  // ---------- this browser's lists ----------
  function list(key) { try { return JSON.parse(localStorage.getItem(key) || "[]"); } catch (e) { return []; } }
  function saveList(key, items) { try { localStorage.setItem(key, JSON.stringify(items.slice(0, 300))); } catch (e) { /* storage full or blocked */ } }

  // ---------- who am I + alerts ----------
  let mePromise = null;
  const me = () => (mePromise = mePromise || api("/api/whoami").catch(() => ({ owner: false })));

  function toast(text) {
    const box = document.getElementById("toasts"); if (!box) return;
    const t = el("div", "toast", text); box.appendChild(t);
    setTimeout(() => t.remove(), 7000);
  }
  function describe(ev) {
    if (ev.kind.startsWith("link_")) {
      const item = list("vd-shared").find((x) => x.id === ev.ref);
      if (item) {
        const what = item.kind === "note" ? "Your note" : item.name;
        if (ev.kind === "link_locked") return `${what} was locked after 5 wrong passwords and destroyed.`;
        return ev.text.replace(/^A (file was downloaded|note was read)/, `${what} was ${item.kind === "note" ? "read" : "downloaded"}`);
      }
    }
    if (ev.kind === "request_upload") {
      const r = list("vd-requests").find((x) => x.id === ev.ref);
      if (r) return `New upload for “${r.title}”.`;
    }
    return ev.text;
  }
  async function pollEvents() {
    let last = Number(sessionStorage.getItem("vd-last-event") || "-1");
    try {
      if (last < 0) { const r = await api("/api/events?after=999999999"); last = r.latest; sessionStorage.setItem("vd-last-event", last); }
      const r = await api("/api/events?after=" + last);
      r.events.forEach((ev) => {
        const text = describe(ev); toast(text);
        if (window.Notification && Notification.permission === "granted" && document.hidden) new Notification("VanishDrop", { body: text });
        last = Math.max(last, ev.n);
      });
      sessionStorage.setItem("vd-last-event", last);
      document.dispatchEvent(new CustomEvent("vd-events", { detail: r.events }));
    } catch (e) { /* server restarting; try again next tick */ }
  }

  async function chatBadge() {
    const b = document.getElementById("chat-badge");
    if (!b || document.body.classList.contains("page-chat")) return;
    try {
      const s = await api("/api/chat/state");
      const n = s.friends.reduce((a, f) => a + f.unread, 0);
      b.textContent = n; b.hidden = !n;
    } catch (e) { /* ignore */ }
  }
  me().then((m) => {
    const chip = document.getElementById("device-chip");
    if (chip && m.owner) chip.textContent = m.name;
    if (m.owner) { pollEvents(); setInterval(pollEvents, 4000); chatBadge(); setInterval(chatBadge, 5000); }
  });
  if (!canCrypto()) {
    const b = document.getElementById("insecure-banner"); if (b) b.hidden = false;
    // On the computer running VanishDrop, the same page works at localhost.
    async function chatBadge() {
    const b = document.getElementById("chat-badge");
    if (!b || document.body.classList.contains("page-chat")) return;
    try {
      const s = await api("/api/chat/state");
      const n = s.friends.reduce((a, f) => a + f.unread, 0);
      b.textContent = n; b.hidden = !n;
    } catch (e) { /* ignore */ }
  }
  me().then((m) => {
      const a = document.getElementById("open-local");
      if (!a) return;
      a.href = `http://localhost:${location.port || 80}${location.pathname}${window.VD_FRAGMENT ? "#" + window.VD_FRAGMENT : ""}`;
      a.hidden = false;
      const t = document.getElementById("local-fix");
      if (t) t.textContent = "If this is the computer running VanishDrop, open it at localhost instead. On other devices, VanishDrop must run with --https.";
    });
  }

  // ---------- scam link checker ----------
  const OFFICIAL = {
    sbi: ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com"], hdfc: ["hdfcbank.com", "hdfc.com"],
    icici: ["icicibank.com"], axis: ["axisbank.com"], kotak: ["kotak.com"], paytm: ["paytm.com", "paytmbank.com"],
    phonepe: ["phonepe.com"], gpay: ["google.com"], amazon: ["amazon.in", "amazon.com"], flipkart: ["flipkart.com"],
    google: ["google.com", "google.co.in", "youtube.com"], whatsapp: ["whatsapp.com", "whatsapp.net", "wa.me"],
    instagram: ["instagram.com"], facebook: ["facebook.com", "fb.com"], netflix: ["netflix.com"],
    uidai: ["uidai.gov.in"], aadhaar: ["uidai.gov.in"], incometax: ["incometax.gov.in"], irctc: ["irctc.co.in"],
    npci: ["npci.org.in"], microsoft: ["microsoft.com", "live.com", "office.com"], apple: ["apple.com", "icloud.com"],
  };
  const RISKY_TLDS = ["xyz", "top", "click", "zip", "mov", "loan", "work", "gq", "tk", "ml", "cf", "ga", "buzz", "rest", "cam", "icu", "monster", "live", "shop"];
  const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "ow.ly", "t.ly", "tiny.cc"];
  const SCAM_WORDS = ["kyc", "verify", "update", "reward", "prize", "lottery", "refund", "otp", "blocked", "suspend", "winner", "free-gift", "claim"];
  function checkLink(raw) {
    const reasons = []; let danger = false;
    let u;
    try { u = new URL(raw); } catch (e) { return { level: "warn", url: raw, reasons: ["This isn't a valid web address."] }; }
    const host = u.hostname.toLowerCase();
    const isOfficial = (h, list) => list.some((d) => h === d || h.endsWith("." + d));
    if (u.username || u.password || /@/.test(raw.split("/")[2] || "")) { danger = true; reasons.push("It hides the real address behind an @ sign."); }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) { danger = true; reasons.push("It uses a bare IP address instead of a website name."); }
    if (host.split(".").some((p) => p.startsWith("xn--"))) { danger = true; reasons.push("It uses look-alike letters from other alphabets."); }
    const plain = host.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s").replace(/rn/g, "m").replace(/vv/g, "w");
    for (const [brand, list] of Object.entries(OFFICIAL)) {
      if ((host.includes(brand) || plain.includes(brand)) && !isOfficial(host, list)) {
        danger = true; reasons.push(`It looks like ${brand.toUpperCase()} but isn't ${list[0]}.`); break;
      }
    }
    const tld = host.split(".").pop();
    if (RISKY_TLDS.includes(tld)) reasons.push(`The ending .${tld} is often used by scam sites.`);
    if (SHORTENERS.some((d) => host === d || host.endsWith("." + d))) reasons.push("It's a short link, so you can't see where it really goes.");
    const words = SCAM_WORDS.filter((w) => (host + u.pathname).toLowerCase().includes(w));
    if (words.length) reasons.push(`It uses words that scams often use: ${words.slice(0, 3).join(", ")}.`);
    if (host.split(".").length > 4) reasons.push("It has an unusually long chain of sub-names.");
    if (u.protocol === "http:") reasons.push("It isn't encrypted (http, not https).");
    return { level: danger ? "danger" : reasons.length ? "warn" : "ok", url: raw, host, reasons };
  }
  function linkWarning(check) {
    const box = el("div", "link-warn " + (check.level === "danger" ? "danger" : "warn"));
    box.appendChild(el("strong", null, check.level === "danger" ? "Suspicious link: don't open it or enter details" : "Check this link before opening"));
    const ul = el("ul");
    check.reasons.forEach((r) => ul.appendChild(el("li", null, r)));
    box.appendChild(ul);
    return box;
  }

  window.VD = {
    toB64, fromB64, canCrypto, keysFromSecret, secretFromPassword, encrypt, decrypt, encryptText, decryptText,
    newRequestKeys, exportPublic, importPublic, sealForRequest, openFromRequest, checkCode, keyStore,
    api, upload, download, saveBlob, bytes, timeLeft, ago, ext, el, setProgress, qrDataUrl, copy, list, saveList,
    me, toast, describe, checkLink, linkWarning,
  };
})();
