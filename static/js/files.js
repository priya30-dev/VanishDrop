(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const { el } = VD;
  let items = VD.list("vd-shared"), status = {};
  const LABEL = { active: "Waiting", downloaded: "Opened and destroyed", expired: "Expired", revoked: "Destroyed by you",
    locked: "Locked: too many wrong passwords", missing: "Not on this computer" };

  async function refresh() {
    if (items.length) {
      try { status = await VD.api("/api/links/status", { json: { items: items.map((f) => ({ id: f.id, token: f.token })) } }); }
      catch (e) { /* keep last */ }
    }
    render();
  }

  function render() {
    $("empty").hidden = items.length > 0; $("stats").hidden = !items.length;
    let live = 0, gone = 0, other = 0;
    const rows = items.map((f) => {
      const s = status[f.id] || { status: "active", downloads: 0, max_downloads: f.max, expires: f.expires };
      const st = s.status;
      if (st === "active") live++; else if (st === "downloaded") gone++; else other++;
      const row = el("article", "file-row" + (st === "active" ? "" : " ended"));
      const icon = el("div", "file-icon" + (f.kind === "note" ? " note" : ""), f.kind === "note" ? "NOTE" : VD.ext(f.name));
      const main = el("div", "item-main");
      main.appendChild(el("p", "item-title", f.kind === "note" ? "Secret note" : f.name));
      main.appendChild(el("p", "item-sub", `${VD.bytes(f.size)} · shared ${VD.ago(f.created)}${f.password ? " · password" : ""}`));
      const state = el("div", "row-state");
      state.appendChild(el("span", "pill " + (st === "active" ? "pill-active" : st === "downloaded" ? "pill-done" : st === "locked" ? "pill-bad" : ""), LABEL[st] || st));
      const verb = f.kind === "note" ? "reads" : "downloads";
      const when = st === "active" ? `disappears in ${VD.timeLeft(s.expires)}` : s.ended_at ? `ended ${VD.ago(s.ended_at)}` : "";
      state.appendChild(el("span", "item-sub", `${s.downloads ?? 0} of ${s.max_downloads ?? f.max} ${verb}${s.failures ? ` · ${s.failures} wrong password${s.failures === 1 ? "" : "s"}` : ""} · ${when}`));
      const actions = el("div", "item-actions");
      if (st === "active") {
        const copy = el("button", "btn btn-sm btn-ghost", "Copy link"); copy.type = "button";
        copy.addEventListener("click", () => VD.copy(f.link, copy));
        const kill = el("button", "btn btn-sm btn-danger", "Destroy now"); kill.type = "button";
        kill.addEventListener("click", async () => {
          if (kill.dataset.armed !== "1") { kill.dataset.armed = "1"; kill.textContent = "Click again to destroy"; setTimeout(() => { kill.dataset.armed = ""; kill.textContent = "Destroy now"; }, 3000); return; }
          kill.disabled = true;
          try { await VD.api(`/api/links/${f.id}/destroy`, { json: { owner_token: f.token } }); } catch (e) { VD.toast(e.message); }
          refresh();
        });
        actions.append(copy, kill);
      } else {
        const rm = el("button", "btn btn-sm btn-quiet", "Remove from list"); rm.type = "button";
        rm.addEventListener("click", () => { items = items.filter((x) => x.id !== f.id); VD.saveList("vd-shared", items); render(); });
        actions.append(rm);
      }
      row.append(icon, main, state, actions);
      return row;
    });
    $("file-list").replaceChildren(...rows);
    $("st-live").textContent = live; $("st-gone").textContent = gone; $("st-other").textContent = other;
  }

  async function loadEvents() {
    try {
      const r = await VD.api("/api/events");
      $("events").replaceChildren(...r.events.map((ev) => {
        const d = el("div", "event", VD.describe(ev));
        const t = el("time", null, VD.ago(ev.at)); d.appendChild(t); return d;
      }));
      $("events-empty").hidden = r.events.length > 0;
    } catch (e) { /* ignore */ }
  }

  if (window.Notification && Notification.permission === "default") {
    $("notify-btn").hidden = false;
    $("notify-btn").addEventListener("click", async () => { await Notification.requestPermission(); $("notify-btn").hidden = true; });
  }
  document.addEventListener("vd-events", () => { refresh(); loadEvents(); });
  refresh(); loadEvents();
  setInterval(refresh, 6000);
  setInterval(render, 1000);
})();
