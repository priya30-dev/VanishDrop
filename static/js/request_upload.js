(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const reqId = $("up-root").dataset.reqId;
  const MAX = 100 * 1024 * 1024;
  let info = null, publicKey = null, timer = null, shouldClean = () => false;

  const show = (id) => ["up-loading", "up-form", "up-done", "up-closed"].forEach((s) => ($(s).hidden = s !== id));
  const showError = (m) => { $("up-error").textContent = m || ""; $("up-error").hidden = !m; };
  function closed(title, text) { if (title) $("up-closed-title").textContent = title; if (text) $("up-closed-text").textContent = text; clearInterval(timer); show("up-closed"); }

  async function load() {
    if (!reqId) return closed("This link doesn't work", "Check you copied the whole link.");
    try { info = await VD.api(`/api/requests/${reqId}`); }
    catch (e) { return closed("This link doesn't work", "Check you copied the whole link, or ask for a new one."); }
    if (info.status !== "open") return closed();
    $("up-owner").textContent = info.owner_name; $("up-owner2").textContent = info.owner_name;
    $("up-title").textContent = info.title;
    $("up-code").textContent = await VD.checkCode(info.public_key).catch(() => "—");
    const tick = () => { $("up-countdown").textContent = VD.timeLeft(info.expires); if (info.expires <= Date.now() / 1000) closed(); };
    tick(); timer = setInterval(tick, 1000);
    show("up-form");
    if (!VD.canCrypto()) { showError("This page can't encrypt here. Ask the person who sent the link to run VanishDrop with --https."); $("up-btn").disabled = true; return; }
    try { publicKey = await VD.importPublic(info.public_key); }
    catch (e) { showError("This request's key is invalid, so uploading isn't safe."); $("up-btn").disabled = true; }
  }

  $("up-file").addEventListener("change", () => {
    const f = $("up-file").files[0]; showError("");
    $("up-file-name").textContent = f ? `${f.name} · ${VD.bytes(f.size)}` : "Choose a file";
    shouldClean = () => false;
    if (f) VD.photo.attach(f, $("up-privacy")).then((fn) => (shouldClean = fn)); else $("up-privacy").hidden = true;
  });

  $("up-form").addEventListener("submit", async (e) => {
    e.preventDefault(); showError("");
    const name = $("up-name").value.trim();
    let f = $("up-file").files[0];
    if (!name) return showError("Add your name so they know who sent it.");
    if (!f) return showError("Choose a file to upload.");
    if (f.size === 0) return showError("That file is empty.");
    if (f.size > MAX) return showError("Files can be up to 100 MB.");
    $("up-btn").disabled = true; $("up-progress").hidden = false;
    try {
      if (shouldClean()) { VD.setProgress("up-progress", "Removing hidden photo details…", 0.02); f = (await VD.photo.clean(f)).file; }
      VD.setProgress("up-progress", "Encrypting with their public key…", 0.05);
      const sealed = await VD.sealForRequest(publicKey, await f.arrayBuffer(),
        JSON.stringify({ name: f.name, type: f.type || "application/octet-stream", from: name.slice(0, 60) }));
      const form = new FormData();
      form.append("blob", new Blob([sealed.blob]), "blob.bin");
      form.append("enc_meta", sealed.meta); form.append("wrapped_key", sealed.wrapped);
      await VD.upload(`/api/requests/${reqId}/upload`, form, (x) => VD.setProgress("up-progress", "Uploading…", 0.2 + x * 0.8));
      $("up-done-text").textContent = `${f.name} is locked so only ${info.owner_name} can open it.`;
      clearInterval(timer); show("up-done");
    } catch (ex) {
      showError(ex.message); $("up-btn").disabled = false; $("up-progress").hidden = true;
    }
  });
  $("up-another").addEventListener("click", () => location.reload());

  load();
})();
