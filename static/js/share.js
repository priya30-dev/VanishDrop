(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const kind = $("share-root").dataset.kind;
  const MAX = 200 * 1024 * 1024, NOTE_MAX = 20000;
  let chosen = null, shouldClean = () => false;

  const btn = $("share-btn"), usePw = $("use-password"), pw = $("password"), errBox = $("share-error");
  const showError = (m) => { errBox.textContent = m || ""; errBox.hidden = !m; };

  if (kind === "file") {
    const drop = $("drop"), input = $("file-input");
    const choose = (file) => {
      showError("");
      if (!file) return;
      if (file.size > MAX) return showError("That file is over 200 MB. For bigger files, use Nearby.");
      if (file.size === 0) return showError("That file is empty. Choose another one.");
      chosen = file;
      drop.classList.add("has-file");
      $("drop-glyph").textContent = VD.ext(file.name);
      $("drop-title").textContent = file.name;
      $("drop-hint").textContent = VD.bytes(file.size) + " · choose a different file";
      btn.disabled = false;
      VD.photo.attach(file, $("photo-privacy")).then((fn) => (shouldClean = fn));
    };
    input.addEventListener("change", () => choose(input.files[0]));
    ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("dragging"); }));
    ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("dragging"); }));
    drop.addEventListener("drop", (e) => choose(e.dataTransfer.files[0]));
  } else {
    const ta = $("note-text");
    ta.addEventListener("input", () => {
      showError("");
      $("note-count").textContent = `${ta.value.length.toLocaleString()} / 20,000 characters`;
      btn.disabled = !ta.value.trim();
    });
  }

  usePw.addEventListener("change", () => {
    $("pw-field").hidden = !usePw.checked; $("tag-pw").hidden = !usePw.checked;
    if (usePw.checked) pw.focus();
    showError("");
  });
  pw.addEventListener("input", () => showError(""));

  btn.addEventListener("click", async () => {
    showError("");
    if (!VD.canCrypto()) return showError("This page can't encrypt here. Open it at http://localhost.");
    let data, meta;
    if (kind === "file") {
      if (!chosen) return showError("Choose a file first.");
    } else {
      const text = $("note-text").value;
      if (!text.trim()) return showError("Write something first.");
      if (text.length > NOTE_MAX) return showError("Notes can be up to 20,000 characters.");
      data = new TextEncoder().encode(text);
      meta = { name: "Secret note", type: "text/plain" };
    }
    if (usePw.checked && pw.value.length < 8) { pw.focus(); return showError("Use a password of at least 8 characters."); }

    btn.disabled = true;
    $("progress").hidden = false;
    try {
      if (kind === "file") {
        VD.setProgress("progress", "Reading file…", 0.03);
        let source = chosen;
        if (shouldClean()) {
          VD.setProgress("progress", "Removing hidden photo details…", 0.05);
          source = (await VD.photo.clean(chosen)).file;
        }
        data = await source.arrayBuffer();
        meta = { name: chosen.name, type: chosen.type || "application/octet-stream" };
      }
      let secret, salt = null;
      if (usePw.checked) {
        salt = VD.toB64(crypto.getRandomValues(new Uint8Array(16)));
        VD.setProgress("progress", "Turning your password into a key…", 0.08);
        secret = await VD.secretFromPassword(pw.value, salt);
      } else {
        secret = crypto.getRandomValues(new Uint8Array(32));
      }
      const { encKey, auth } = await VD.keysFromSecret(secret);
      VD.setProgress("progress", "Encrypting on this device…", 0.2);
      const blob = await VD.encrypt(encKey, data);
      const encMeta = await VD.encryptText(encKey, JSON.stringify(meta));

      const form = new FormData();
      form.append("blob", new Blob([blob]), "blob.bin");
      form.append("kind", kind);
      form.append("enc_meta", encMeta);
      form.append("auth", auth);
      form.append("expires_in", $("expiry").value);
      form.append("max_downloads", $("downloads").value);
      form.append("password", usePw.checked ? "1" : "0");
      if (salt) form.append("salt", salt);
      const res = await VD.upload("/api/links", form, (f) => VD.setProgress("progress", "Uploading encrypted data…", 0.35 + f * 0.65));

      const who = await VD.me();
      // Without HTTPS only this computer can decrypt, so give a localhost link that always works here.
      const base = who.https ? who.lan_url : location.origin;
      const link = `${base}/d/${res.id}` + (usePw.checked ? "" : `#${VD.toB64(secret)}`);
      secret.fill(0);
      const items = VD.list("vd-shared");
      items.unshift({ id: res.id, token: res.owner_token, kind, name: meta.name, size: data.byteLength, cleaned: shouldClean(),
        created: Date.now() / 1000, expires: res.expires, link, max: Number($("downloads").value), password: usePw.checked });
      VD.saveList("vd-shared", items);
      if (kind === "note") $("note-text").value = "";
      showResult(link, meta.name, who);
    } catch (e) {
      showError(e.message || "Something went wrong while sharing. Try again.");
      btn.disabled = false; $("progress").hidden = true;
    }
  });

  function showResult(link, name, who) {
    $("composer").hidden = true; $("result").hidden = false;
    $("share-link").value = link;
    const dl = Number($("downloads").value), exp = $("expiry").selectedOptions[0].textContent;
    const what = kind === "note" ? "Secret note · burns after 1 read" : `${name} · ${dl === 1 ? "destroyed after 1 download" : dl + " downloads allowed"}`;
    $("result-summary").textContent = `${what} · expires in ${exp}`;
    $("pw-note").hidden = !usePw.checked;
    $("https-warn").hidden = !!who.https;
    const msg = kind === "note" ? "I've sent you a secret note. It disappears after you read it: " : "I've shared a file with you. It disappears after you download it: ";
    $("wa-btn").href = "https://wa.me/?text=" + encodeURIComponent(msg + link);
    $("qr").src = VD.qrDataUrl(link);
    $("copy-btn").focus();
  }
  $("copy-btn").addEventListener("click", () => VD.copy($("share-link").value, $("copy-btn")));
  $("again-btn").addEventListener("click", () => location.reload());
})();
