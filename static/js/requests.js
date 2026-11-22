(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const { el } = VD;
  const KEY = "vd-requests";
  const HISTORY = "vd-request-history";   // who sent what, kept only in this browser
  const metaCache = new Map();

  const showError = (m) => { $("req-error").textContent = m || ""; $("req-error").hidden = !m; };

  $("req-form").addEventListener("submit", async (e) => {
    e.preventDefault(); showError("");
    if (!VD.canCrypto()) return showError("This page can't create keys here. Open it at http://localhost.");
    const title = $("req-title").value.trim();
    if (!title) return showError("Say what you're collecting.");
    $("req-btn").disabled = true; $("req-btn").textContent = "Creating your key pair…";
    try {
      const keys = await VD.newRequestKeys();
      const pub = await VD.exportPublic(keys.publicKey);
      const res = await VD.api("/api/requests", { json: { title, public_key: pub, expires_in: Number($("req-expiry").value), max_uploads: Number($("req-max").value) } });
      await VD.keyStore.put("req:" + res.id, keys.privateKey);
      const items = VD.list(KEY); items.unshift({ id: res.id, token: res.owner_token, title, created: Date.now() / 1000 }); VD.saveList(KEY, items);
      const who = await VD.me();
      const link = `${who.https ? who.lan_url : location.origin}/r/${res.id}`;
      $("req-link").value = link; $("req-code").textContent = await VD.checkCode(pub);
      $("req-https-warn").hidden = !!who.https;
      $("req-qr").src = VD.qrDataUrl(link);
      $("req-form").hidden = true; $("req-result").hidden = false;
      refresh();
    } catch (ex) { showError(ex.message); }
    finally { $("req-btn").disabled = false; $("req-btn").textContent = "Create upload link"; }
  });
  $("req-copy").addEventListener("click", () => VD.copy($("req-link").value, $("req-copy")));
  $("req-again").addEventListener("click", () => { $("req-form").reset(); $("req-form").hidden = false; $("req-result").hidden = true; });

  async function describeUpload(privateKey, up) {
    if (metaCache.has(up.id)) return metaCache.get(up.id);
    let meta = null;
    try { const key = await VD.openFromRequest(privateKey, up.wrapped_key); meta = JSON.parse(await VD.decryptText(key, up.enc_meta)); meta._key = key; }
    catch (e) { meta = { name: "Couldn't decrypt", from: "?", broken: true }; }
    metaCache.set(up.id, meta);
    return meta;
  }

  async function refresh() {
    const items = VD.list(KEY);
    $("req-empty").hidden = items.length > 0;
    if (!items.length) { $("req-list").replaceChildren(); return; }
    let status;
    try { status = await VD.api("/api/requests/status", { json: { items: items.map((r) => ({ id: r.id, token: r.token })) } }); }
    catch (e) { return; }
    const who = await VD.me();
    const cards = [];
    for (const r of items) {
      const st = status[r.id] || { status: "missing" };
      const card = el("section", "card");
      const head = el("div", "card-head");
      const left = el("div");
      left.appendChild(el("h2", null, r.title));
      const sub = st.status === "missing" ? "Not on this computer any more"
        : `${st.received} of ${st.max_uploads} received · ${st.uploads.length} waiting to be saved · ${st.status === "open" ? "closes in " + VD.timeLeft(st.expires) : "closed"}`;
      left.appendChild(el("p", "muted small", sub));
      head.appendChild(left);
      const pill = el("span", "pill " + (st.status === "open" ? "pill-active" : ""), st.status === "open" ? "Open" : st.status === "missing" ? "Gone" : "Closed");
      head.appendChild(pill);
      card.appendChild(head);

      if (st.status !== "missing") {
        const actions = el("div", "row");
        const copy = el("button", "btn btn-sm btn-ghost", "Copy link"); copy.type = "button";
        copy.addEventListener("click", () => VD.copy(`${who.https ? who.lan_url : location.origin}/r/${r.id}`, copy));
        const close = el("button", "btn btn-sm btn-danger", "Close and wipe all"); close.type = "button";
        close.addEventListener("click", async () => {
          if (close.dataset.armed !== "1") { close.dataset.armed = "1"; close.textContent = "Click again to wipe"; return; }
          await VD.api(`/api/requests/${r.id}/close`, { method: "POST", headers: { "X-VD-Owner": r.token } });
          refresh();
        });
        actions.append(copy, close);
        card.appendChild(actions);
      }

      const privateKey = await VD.keyStore.get("req:" + r.id).catch(() => null);
      const list = el("div", "list");
      if (st.uploads && st.uploads.length) {
        if (!privateKey) list.appendChild(el("p", "warn", "This request's private key is in the browser you created it in. Open VanishDrop there to read these files."));
        for (const up of st.uploads) {
          const meta = privateKey ? await describeUpload(privateKey, up) : { name: "Locked file", from: "?" };
          const row = el("div", "item");
          row.appendChild(el("div", "avatar", VD.ext(meta.name).slice(0, 3)));
          const main = el("div", "item-main");
          main.appendChild(el("p", "item-title", meta.name));
          main.appendChild(el("p", "item-sub", `From ${meta.from} · ${VD.bytes(Math.max(up.size - 28, 0))} · ${VD.ago(up.created)}`));
          row.appendChild(main);
          if (privateKey && !meta.broken) {
            const save = el("button", "btn btn-sm btn-primary", "Save and wipe"); save.type = "button";
            save.addEventListener("click", () => saveUpload(r, up, meta, save));
            const a = el("div", "item-actions"); a.appendChild(save); row.appendChild(a);
          }
          list.appendChild(row);
        }
      }
      const saved = VD.list(HISTORY).filter((h) => h.req === r.id);
      if (!(st.uploads && st.uploads.length) && st.status !== "missing") {
        list.appendChild(el("p", "help", saved.length ? "Nothing new to save." : "No uploads yet. Share the link and the check code."));
      }
      card.appendChild(list);
      if (saved.length) {
        card.appendChild(el("h3", "small-head", "Saved earlier"));
        const hist = el("div", "list");
        saved.forEach((h) => {
          const row = el("div", "item");
          row.appendChild(el("div", "avatar friend", VD.ext(h.name).slice(0, 3)));
          const main = el("div", "item-main");
          main.appendChild(el("p", "item-title", h.name));
          main.appendChild(el("p", "item-sub", `From ${h.from} · ${VD.bytes(h.size)} · saved ${VD.ago(h.saved)}`));
          row.appendChild(main); hist.appendChild(row);
        });
        card.appendChild(hist);
      }
      if (st.status === "missing") {
        const rm = el("button", "btn btn-sm btn-quiet", "Remove from list"); rm.type = "button";
        rm.addEventListener("click", async () => { VD.saveList(KEY, VD.list(KEY).filter((x) => x.id !== r.id)); VD.saveList(HISTORY, VD.list(HISTORY).filter((h) => h.req !== r.id)); await VD.keyStore.del("req:" + r.id).catch(() => {}); refresh(); });
        card.appendChild(rm);
      }
      cards.push(card);
    }
    $("req-list").replaceChildren(...cards);
  }

  async function saveUpload(r, up, meta, btn) {
    btn.disabled = true; btn.textContent = "Decrypting…";
    try {
      const { data } = await VD.download(`/api/requests/${r.id}/uploads/${up.id}/blob`, up.size, null, { "X-VD-Owner": r.token });
      const plain = await VD.decrypt(meta._key, data);
      VD.saveBlob(plain, meta.name, meta.type);
      const hist = VD.list(HISTORY);
      hist.unshift({ req: r.id, name: meta.name, from: meta.from, size: plain.byteLength, saved: Date.now() / 1000 });
      VD.saveList(HISTORY, hist);
      await VD.api(`/api/requests/${r.id}/uploads/${up.id}/delete`, { method: "POST", headers: { "X-VD-Owner": r.token } });
      metaCache.delete(up.id);
      VD.toast(`Saved ${meta.name}. Its encrypted copy was wiped from the server.`);
      refresh();
    } catch (e) {
      VD.toast(e.name === "OperationError" ? "That file failed its integrity check, so it wasn't saved." : e.message);
      btn.disabled = false; btn.textContent = "Save and wipe";
    }
  }

  refresh();
  document.addEventListener("vd-events", (e) => { if (e.detail.some((ev) => ev.kind === "request_upload")) refresh(); });
  setInterval(refresh, 15000);
})();
