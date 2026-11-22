(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const { el } = VD;
  let state = null, sendTo = null, shouldClean = () => false;
  const decided = new Set();

  function initial(name) { return (name || "?").trim().charAt(0).toUpperCase(); }

  function itemRow({ avatar, friend, title, sub, actions, bar }) {
    const row = el("div", "item");
    if (avatar != null) row.appendChild(el("div", "avatar" + (friend ? " friend" : ""), avatar));
    const main = el("div", "item-main");
    main.appendChild(el("p", "item-title", title));
    if (sub) main.appendChild(el("p", "item-sub", sub));
    if (bar != null) { const b = el("div", "mini-bar"); const s = el("span"); s.style.width = Math.round(bar * 100) + "%"; b.appendChild(s); main.appendChild(b); }
    row.appendChild(main);
    if (actions && actions.length) { const a = el("div", "item-actions"); actions.forEach((x) => a.appendChild(x)); row.appendChild(a); }
    return row;
  }
  function button(text, cls, onClick) { const b = el("button", "btn btn-sm " + cls, text); b.type = "button"; b.addEventListener("click", onClick); return b; }
  function fill(boxId, emptyId, rows) {
    const box = $(boxId); box.replaceChildren(...rows); $(emptyId).hidden = rows.length > 0;
  }
  // Only rebuild a section when its data changed, so buttons aren't swapped out mid-click.
  const sigs = {};
  function changed(key, data) {
    const sig = JSON.stringify(data);
    if (sigs[key] === sig) return false;
    sigs[key] = sig; return true;
  }

  function render() {
    const s = state;
    // This device
    if (document.activeElement !== $("dev-name")) $("dev-name").value = s.me.name;
    $("me-kv").replaceChildren(
      el("dt", null, "Address"), el("dd", "mono", s.me.ip),
      el("dt", null, "Ports"), el("dd", "mono", `UDP ${s.me.udp} · TCP ${s.me.tcp}`),
      el("dt", null, "Key ID"), el("dd", "mono", s.me.fp.slice(0, 16).match(/.{4}/g).join(" ")));
    $("auto-accept").checked = s.settings.auto_accept;
    $("allow-plain").checked = s.settings.allow_plain;

    // Decisions waiting for me
    const pendList = s.pending.filter((p) => !decided.has(p.id));
    pendList.forEach((p) => { const t = document.querySelector(`[data-expires="${p.id}"]`); if (t) t.textContent = `Expires in ${p.seconds_left}s`; });
    if (changed("pending", pendList.map(({ seconds_left, ...rest }) => rest))) {
    const pend = s.pending.filter((p) => !decided.has(p.id)).map((p) => {
      const card = el("section", "card decision");
      const isFile = p.kind === "file";
      card.appendChild(el("h2", null, isFile ? `${p.peer_name} wants to send you a file` : `${p.peer_name} wants to be friends`));
      if (isFile) card.appendChild(el("p", null, `${p.name} · ${VD.bytes(p.size)}`));
      const tags = el("div", "tags");
      tags.appendChild(el("span", p.friend ? "tag tag-ok" : "tag", p.friend ? "Verified friend" : "Not a friend yet"));
      if (p.impostor) tags.appendChild(el("span", "tag tag-bad", `Not your saved ${p.peer_name}: different key`));
      if (p.plain) tags.appendChild(el("span", "tag tag-warn", "Unencrypted demo transfer"));
      card.appendChild(tags);
      card.appendChild(el("p", "help", "Safety code. Ask them to read theirs out. Only accept if it's exactly the same:"));
      card.appendChild(el("p", "code", p.code));
      const row = el("div", "row");
      row.appendChild(button("Accept", "btn-primary", () => decide(p.id, true)));
      row.appendChild(button("Decline", "btn-ghost", () => decide(p.id, false)));
      const exp = el("span", "help", `Expires in ${p.seconds_left}s`); exp.dataset.expires = p.id; row.appendChild(exp);
      card.appendChild(row);
      return card;
    });
    $("pending").replaceChildren(...pend);
    }

    // Devices
    if (changed("peers", s.peers)) fill("peers", "peers-empty", s.peers.map((p) => itemRow({
      avatar: initial(p.name), friend: p.friend, title: p.name,
      sub: (p.friend ? "Friend · " : "") + p.ip,
      actions: [
        button("Send a file", "btn-primary", () => openSend(p)),
        ...(p.friend ? [] : [button("Pair", "btn-ghost", () => pair(p))]),
      ],
    })));

    // Transfers: outgoing jobs, pairings, incoming progress
    const rows = [];
    s.pairings.forEach((p) => {
      const label = { connecting: "Connecting…", waiting: `Waiting for them to accept. Safety code ${p.code}`, paired: "Paired. You're now friends.",
        declined: p.error, failed: p.error }[p.status];
      rows.push(itemRow({ avatar: initial(p.peer_name), title: `Pairing with ${p.peer_name || "device"}`, sub: label }));
    });
    s.jobs.forEach((j) => {
      const frac = j.size ? j.sent / j.size : 0;
      const sub = {
        queued: "Queued", hashing: "Preparing (calculating fingerprint)…", connecting: "Connecting…",
        waiting: j.friend ? "Starting…" : `Waiting for ${j.peer_name} to accept. Safety code ${j.code}`,
        sending: `Sending ${VD.bytes(j.sent)} of ${VD.bytes(j.size)}${j.plain ? " · UNENCRYPTED demo" : " · encrypted"}${j.resumed_from ? ` · resumed at ${VD.bytes(j.resumed_from)}` : ""}`,
        delivered: `Delivered to ${j.peer_name} and checked`, declined: j.error, failed: j.error,
      }[j.status];
      const actions = [];
      if (j.status === "failed" || j.status === "declined") actions.push(button("Retry", "btn-ghost", () => jobAction(j.id, "retry")));
      if (["failed", "declined", "delivered", "queued"].includes(j.status)) actions.push(button("Remove", "btn-quiet", () => jobAction(j.id, "cancel")));
      rows.push(itemRow({ avatar: "↑", title: `${j.name} → ${j.peer_name || "device"}`, sub, actions,
        bar: j.status === "sending" ? frac : null }));
    });
    s.receiving.filter((r) => r.status === "receiving").forEach((r) => {
      rows.push(itemRow({ avatar: "↓", title: `${r.name} ← ${r.peer_name}`, sub: `Receiving ${VD.bytes(r.got)} of ${VD.bytes(r.size)}`, bar: r.got / r.size }));
    });
    if (changed("jobs", [s.pairings, s.jobs, s.receiving])) fill("jobs", "jobs-empty", rows);

    // Inbox
    if (changed("inbox", s.inbox)) fill("inbox", "inbox-empty", s.inbox.map((f) => {
      const open = el("a", "btn btn-sm btn-primary", "Save"); open.href = `/api/nearby/inbox/${f.id}`;
      return itemRow({ avatar: VD.ext(f.name).slice(0, 3), title: f.name,
        sub: `${VD.bytes(f.size)} from ${f.from_name}${f.friend ? " (verified friend)" : " (signature checked)"}${f.plain ? " · sent UNENCRYPTED" : ""} · ${VD.ago(f.received)}`,
        actions: [open, button("Delete", "btn-danger", async (e) => {
          if (e.target.dataset.armed !== "1") { e.target.dataset.armed = "1"; e.target.textContent = "Click again"; return; }
          await VD.api(`/api/nearby/inbox/${f.id}/delete`, { method: "POST" }); refresh();
        })] });
    }));

    // Friends
    if (changed("friends", s.friends)) fill("friends", "friends-empty", s.friends.map((f) => itemRow({
      avatar: initial(f.name), friend: true, title: f.name, sub: "Key " + f.fp.slice(0, 16).match(/.{4}/g).join(" "),
      actions: [button("Remove", "btn-quiet", async () => { await VD.api("/api/nearby/friends/remove", { json: { fp: f.fp } }); refresh(); })],
    })));
  }

  async function refresh() {
    try { state = await VD.api("/api/nearby/state"); render(); }
    catch (e) { /* server restarting */ }
  }
  async function decide(id, accept) {
    decided.add(id);
    try { await VD.api(`/api/nearby/pending/${id}`, { json: { accept } }); } catch (e) { VD.toast(e.message); }
    refresh();
  }
  async function pair(p) {
    try { await VD.api("/api/nearby/pair", { json: { fp: p.fp } }); VD.toast(`Pairing with ${p.name}. Compare the safety code on both screens.`); }
    catch (e) { VD.toast(e.message); }
    refresh();
  }
  async function jobAction(id, action) {
    try { await VD.api(`/api/nearby/jobs/${id}/${action}`, { method: "POST" }); } catch (e) { VD.toast(e.message); }
    refresh();
  }

  // Send dialog
  const dialog = $("send-dialog");
  function openSend(p) {
    sendTo = p; $("send-to").textContent = p.name; $("send-file").value = ""; $("send-file-name").textContent = "Choose a file";
    $("send-plain").checked = false; $("send-error").hidden = true; $("send-privacy").hidden = true; shouldClean = () => false; $("send-progress").hidden = true; $("send-go").disabled = false;
    dialog.showModal();
  }
  $("send-file").addEventListener("change", () => {
    const f = $("send-file").files[0]; $("send-file-name").textContent = f ? `${f.name} · ${VD.bytes(f.size)}` : "Choose a file";
    shouldClean = () => false;
    if (f) VD.photo.attach(f, $("send-privacy")).then((fn) => (shouldClean = fn)); else $("send-privacy").hidden = true;
  });
  $("send-form").addEventListener("submit", async (e) => {
    if (e.submitter && e.submitter.value === "cancel") return;
    e.preventDefault();
    let f = $("send-file").files[0];
    const err = (m) => { $("send-error").textContent = m; $("send-error").hidden = false; };
    if (!f) return err("Choose a file first.");
    if (f.size === 0) return err("That file is empty.");
    if (f.size > 4 * 1024 ** 3) return err("Files sent to nearby devices can be up to 4 GB.");
    $("send-go").disabled = true; $("send-progress").hidden = false;
    if (f && shouldClean()) f = (await VD.photo.clean(f)).file;
    const form = new FormData(); form.append("fp", sendTo.fp); form.append("plain", $("send-plain").checked ? "1" : "0"); form.append("file", f);
    try {
      await VD.upload("/api/nearby/send", form, (x) => VD.setProgress("send-progress", "Handing the file to VanishDrop…", x));
      dialog.close(); refresh();
    } catch (ex) { err(ex.message); $("send-go").disabled = false; }
  });

  $("name-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try { await VD.api("/api/nearby/settings", { json: { name: $("dev-name").value } }); VD.toast("Name saved. Nearby devices will see it within a few seconds."); $("dev-name").blur(); }
    catch (ex) { VD.toast(ex.message); }
    refresh();
  });
  $("auto-accept").addEventListener("change", (e) => VD.api("/api/nearby/settings", { json: { auto_accept: e.target.checked } }));
  $("allow-plain").addEventListener("change", (e) => VD.api("/api/nearby/settings", { json: { allow_plain: e.target.checked } }));

  refresh();
  setInterval(refresh, 1200);
})();
