(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const linkId = $("dl-root").dataset.linkId;
  // Read the key from the #fragment, then remove it from the address bar and history.
  const fragment = location.hash.slice(1);
  if (!window.isSecureContext) window.VD_FRAGMENT = fragment;
  if (fragment) history.replaceState(null, "", location.pathname);
  // Opening the same link again in this tab only changes the #part: start over.
  window.addEventListener("hashchange", () => location.reload());
  let info = null, keys = null, meta = null, timer = null;

  const show = (id) => ["dl-loading", "dl-ready", "dl-note", "dl-done", "dl-gone"].forEach((s) => ($(s).hidden = s !== id));
  const showError = (m) => { $("dl-error").textContent = m || ""; $("dl-error").hidden = !m; };

  function gone(status) {
    const t = {
      downloaded: ["This has vanished", "It was already opened, and its encrypted copy was wiped from the server."],
      expired: ["This link has expired", "Its time ran out, and the encrypted copy was wiped."],
      revoked: ["The sender destroyed this", "They removed it before it was opened. Ask them to share it again."],
      locked: ["Locked and destroyed", "Too many wrong passwords were tried, so the file was wiped for safety."],
      missing: ["This link doesn't work", "Check you copied the whole link, or ask the sender to share it again."],
    }[status] || ["This no longer exists", "It was opened or it expired."];
    $("gone-title").textContent = t[0]; $("gone-text").textContent = t[1];
    clearInterval(timer); show("dl-gone");
  }
  function tick() {
    $("countdown").textContent = VD.timeLeft(info.expires);
    if (info.expires <= Date.now() / 1000) gone("expired");
  }
  function updateButton() {
    const left = info.downloads_left;
    const verb = info.kind === "note" ? "Reveal note" : "Download";
    $("dl-btn").textContent = left === 1 ? `${verb} and destroy` : verb;
  }

  async function load() {
    if (!linkId) return gone("missing");
    try { info = await VD.api(`/api/links/${linkId}`); }
    catch (e) { return gone((e.data && e.data.status) || (e.status ? "missing" : "")); }
    const isNote = info.kind === "note";
    $("dl-kicker").textContent = isNote ? "Someone sent you a secret note" : "Someone shared a file with you";
    $("left-label").textContent = isNote ? "Reads left" : "Downloads left";
    $("file-size").textContent = VD.bytes(Math.max(info.size - 28, 0));
    $("left").textContent = info.downloads_left === 1 ? "1 (last one)" : String(info.downloads_left);
    if (isNote) { document.querySelector(".file-icon").classList.add("note"); $("file-ext").textContent = "NOTE"; $("file-name").textContent = "Secret note"; }
    updateButton(); tick(); timer = setInterval(tick, 1000);
    show("dl-ready");
    if (!VD.canCrypto()) { showError("This page can't decrypt here. Use the button at the top, or ask the sender to run VanishDrop with --https."); return; }

    if (info.password) {
      $("pw-form").hidden = false;
      $("attempts").textContent = `${info.attempts_left} tries before the file destroys itself.`;
      if (!isNote) $("file-name").textContent = "Protected file";
      $("dl-password").focus();
    } else if (!fragment) {
      showError("This link is missing its key (the part after #). Ask the sender to copy the whole link.");
    } else {
      try { await unlock(VD.fromB64(fragment)); }
      catch (e) { if (e.status !== 410) showError(e.status === 403 ? "This link's key is wrong or damaged. Ask the sender to copy the whole link." : e.message); }
    }
  }

  async function unlock(secret) {
    const k = await VD.keysFromSecret(secret);
    secret.fill(0);
    let res;
    try { res = await VD.api(`/api/links/${linkId}/open`, { method: "POST", headers: { "X-VD-Auth": k.auth } }); }
    catch (e) {
      if (e.status === 410) gone(e.data.status);
      if (e.data && e.data.attempts_left != null) $("attempts").textContent = `${e.data.attempts_left} tries before the file destroys itself.`;
      throw e;
    }
    keys = k;
    meta = JSON.parse(await VD.decryptText(keys.encKey, res.enc_meta));
    if (info.kind === "file") { $("file-name").textContent = meta.name; $("file-ext").textContent = VD.ext(meta.name); }
    $("pw-form").hidden = true;
    $("dl-btn").disabled = false;
    $("dl-btn").focus();
  }

  $("pw-form").addEventListener("submit", async (e) => {
    e.preventDefault(); showError("");
    const pw = $("dl-password").value;
    if (!pw) { showError("Enter the password the sender gave you."); return; }
    $("unlock-btn").disabled = true; $("unlock-btn").textContent = "Checking…";
    try { await unlock(await VD.secretFromPassword(pw, info.salt)); }
    catch (err) { if (err.status !== 410) showError(err.message); }
    finally { $("unlock-btn").disabled = false; $("unlock-btn").textContent = "Unlock"; }
  });
  $("dl-password").addEventListener("input", () => showError(""));

  $("dl-btn").addEventListener("click", async () => {
    if (!keys) return;
    showError(""); $("dl-btn").disabled = true; $("dl-progress").hidden = false;
    try {
      const { data, headers } = await VD.download(`/api/links/${linkId}/blob`, info.size,
        (f) => VD.setProgress("dl-progress", "Downloading…", f * 0.85), { "X-VD-Auth": keys.auth });
      VD.setProgress("dl-progress", "Decrypting on this device…", 0.92);
      const plain = await VD.decrypt(keys.encKey, data);
      VD.setProgress("dl-progress", "Done", 1);
      const left = Number(headers.get("X-Downloads-Left"));
      clearInterval(timer);
      if (info.kind === "note") {
        const noteText = new TextDecoder().decode(plain);
        $("note-text").textContent = noteText;
        const links = noteText.match(/(https?:\/\/[^\s<>"']+|www\.[^\s<>"']+)/gi) || [];
        const warnBox = $("note-links"); warnBox.replaceChildren();
        links.forEach((l) => {
          const c = VD.checkLink(l.startsWith("www.") ? "http://" + l : l.replace(/[).,!?]+$/, ""));
          if (c.level !== "ok") warnBox.appendChild(VD.linkWarning(c));
        });
        $("note-gone").textContent = left === 0
          ? "This note has been destroyed on the server. Copy it now if you need it: once you leave this page it's gone."
          : `This note can be read ${left} more time${left === 1 ? "" : "s"}.`;
        show("dl-note");
        return;
      }
      VD.saveBlob(plain, meta.name, meta.type);
      if (left === 0) await dissolve();
      $("done-title").textContent = left === 0 ? "Downloaded. The file is gone." : "Downloaded";
      $("done-text").textContent = left === 0
        ? `${meta.name} is saved on your device. The server's encrypted copy has been wiped, so this link won't work again.`
        : `${meta.name} is saved on your device. This link works ${left} more time${left === 1 ? "" : "s"}.`;
      show("dl-done");
    } catch (e) {
      if (e.status === 410) return gone(e.data.status);
      showError(e.name === "OperationError" ? "The file couldn't be decrypted: it may have been changed on the server." : e.message);
      $("dl-btn").disabled = false; $("dl-progress").hidden = true;
    }
  });
  $("note-copy").addEventListener("click", () => VD.copy($("note-text").textContent, $("note-copy")));

  function dissolve() {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return Promise.resolve();
    const tile = $("file-tile"), shards = $("shards"), cols = 14, rows = 5;
    for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
      const s = document.createElement("i");
      s.style.left = (c / cols) * 100 + "%"; s.style.top = (r / rows) * 100 + "%";
      s.style.width = 100 / cols + 0.4 + "%"; s.style.height = 100 / rows + 0.4 + "%";
      s.style.setProperty("--dx", Math.random() * 60 + 20 + "px");
      s.style.setProperty("--dy", -(Math.random() * 50 + 10) + "px");
      s.style.animationDelay = (c / cols) * 520 + Math.random() * 160 + "ms";
      shards.appendChild(s);
    }
    tile.classList.add("dissolving");
    return new Promise((r) => setTimeout(r, 1500));
  }

  load();
})();
