(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const { el } = VD;
  let peer = new URLSearchParams(location.search).get("with") || null;
  let state = null, lastSig = "", friendsSig = "";

  const showError = (m) => { $("chat-error").textContent = m || ""; $("chat-error").hidden = !m; };
  const initial = (n) => (n || "?").trim().charAt(0).toUpperCase();
  const clock = (t) => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  function renderFriends() {
    const sig = JSON.stringify(state.friends.map((f) => [f.fp, f.online, f.unread, f.fp === peer]));
    if (sig === friendsSig) return;
    friendsSig = sig;
    $("no-friends").hidden = state.friends.length > 0;
    $("friend-list").replaceChildren(...state.friends.map((f) => {
      const b = el("button", "friend-btn" + (f.fp === peer ? " active" : "")); b.type = "button";
      b.appendChild(el("span", "avatar friend", initial(f.name)));
      const main = el("span", "item-main");
      main.appendChild(el("span", "item-title", f.name));
      main.appendChild(el("span", "item-sub", f.online ? "On this network" : "Not nearby right now"));
      b.appendChild(main);
      b.appendChild(el("span", "presence " + (f.online ? "on" : "off")));
      if (f.unread) b.appendChild(el("span", "count-badge", String(f.unread)));
      b.addEventListener("click", () => openChat(f.fp));
      return b;
    }));
  }

  // Text with links: links become real anchors, and risky ones get a warning underneath.
  function messageBody(text) {
    const wrap = el("div", "msg-text");
    const warnings = [];
    const re = /(https?:\/\/[^\s<>"']+|www\.[^\s<>"']+)/gi;
    let last = 0, m;
    while ((m = re.exec(text))) {
      if (m.index > last) wrap.appendChild(document.createTextNode(text.slice(last, m.index)));
      let raw = m[0].replace(/[).,!?]+$/, "");
      const url = raw.startsWith("www.") ? "http://" + raw : raw;
      const a = el("a", null, raw); a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer";
      wrap.appendChild(a);
      const check = VD.checkLink(url);
      if (check.level !== "ok") warnings.push(check);
      last = m.index + raw.length;
      re.lastIndex = last;
    }
    if (last < text.length) wrap.appendChild(document.createTextNode(text.slice(last)));
    const box = el("div");
    box.appendChild(wrap);
    warnings.forEach((w) => box.appendChild(VD.linkWarning(w)));
    return box;
  }

  function renderMessages(force) {
    const now = Date.now() / 1000;
    const msgs = state.messages.filter((m) => !m.expires || m.expires > now);
    const sig = JSON.stringify(msgs.map((m) => [m.mid, m.status]));
    if (!force && sig === lastSig) { updateTimers(); return; }
    lastSig = sig;
    const box = $("messages");
    const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
    if (!msgs.length) {
      box.replaceChildren(el("p", "help center chat-hint", "No messages yet. Say hi. Only you two can read this."));
    } else {
      box.replaceChildren(...msgs.map((m) => {
        const row = el("div", "msg " + (m.direction === "out" ? "out" : "in"));
        const bubble = el("div", "bubble");
        bubble.appendChild(messageBody(m.text));
        row.appendChild(bubble);
        const meta = el("div", "msg-meta");
        let status = "";
        if (m.direction === "out") status = { sending: "Sending…", delivered: "Delivered", failed: "Not delivered" }[m.status] || m.status;
        meta.appendChild(el("span", null, clock(m.at) + (status ? " · " + status : "")));
        if (m.expires) { const t = el("span", "timer"); t.dataset.expires = m.expires; meta.appendChild(t); }
        if (m.status === "failed") {
          meta.appendChild(el("span", "msg-error", m.error || ""));
          const r = el("button", "link-btn", "Retry"); r.type = "button";
          r.addEventListener("click", async () => { try { await VD.api(`/api/chat/retry/${m.mid}`, { method: "POST" }); } catch (e) { VD.toast(e.message); } refresh(); });
          meta.appendChild(r);
        }
        row.appendChild(meta);
        return row;
      }));
    }
    updateTimers();
    if (nearBottom || force) box.scrollTop = box.scrollHeight;
  }

  function updateTimers() {
    document.querySelectorAll(".timer").forEach((t) => {
      const left = Number(t.dataset.expires) - Date.now() / 1000;
      t.textContent = left > 0 ? " · disappears in " + VD.timeLeft(Number(t.dataset.expires)) : " · gone";
    });
  }

  function renderHead() {
    const f = state.friends.find((x) => x.fp === peer);
    if (!f) { $("chat-open").hidden = true; $("chat-empty").hidden = false; return; }
    $("chat-empty").hidden = true; $("chat-open").hidden = false;
    $("chat-avatar").textContent = initial(f.name);
    $("chat-name").textContent = f.name;
    $("chat-status").textContent = f.online
      ? "On this network · messages are encrypted end to end"
      : "Not nearby right now. Messages will fail until they're back on your Wi-Fi.";
  }

  async function refresh(force) {
    try {
      state = await VD.api("/api/chat/state" + (peer ? "?peer=" + encodeURIComponent(peer) : ""));
      if (peer && !state.friends.some((f) => f.fp === peer)) peer = null;
      if (!peer && state.friends.length === 1) peer = state.friends[0].fp;
      renderFriends(); renderHead(); if (peer) renderMessages(force);
    } catch (e) { /* server restarting */ }
  }

  function openChat(fp) {
    peer = fp; lastSig = ""; friendsSig = "";
    history.replaceState(null, "", "/chat?with=" + encodeURIComponent(fp));
    showError(""); refresh(true);
    $("msg").focus();
  }

  $("msg").addEventListener("input", () => { showError(""); $("msg-count").textContent = `${$("msg").value.length.toLocaleString()} / 4,000`; });
  $("msg").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("composer").requestSubmit(); } });
  $("composer").addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = $("msg").value.trim();
    if (!text) return showError("Write a message first.");
    $("send").disabled = true;
    try {
      await VD.api("/api/chat/send", { json: { fp: peer, text, ttl: Number($("ttl").value) } });
      $("msg").value = ""; $("msg-count").textContent = "0 / 4,000";
      await refresh(true);
    } catch (ex) { showError(ex.message); }
    finally { $("send").disabled = false; $("msg").focus(); }
  });
  $("chat-clear").addEventListener("click", async (e) => {
    const b = e.currentTarget;
    if (b.dataset.armed !== "1") { b.dataset.armed = "1"; b.textContent = "Click again to clear"; setTimeout(() => { b.dataset.armed = ""; b.textContent = "Clear chat"; }, 3000); return; }
    await VD.api("/api/chat/clear", { json: { fp: peer } });
    b.dataset.armed = ""; b.textContent = "Clear chat"; refresh(true);
  });

  refresh(true);
  setInterval(refresh, 1200);
  setInterval(updateTimers, 1000);
})();
