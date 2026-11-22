(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const { el } = VD;
  let after = 0, paused = false, filter = "all", data = null, selected = null;
  const rows = [];   // newest first, capped
  const MAX_ROWS = 400;

  const EXPLAIN = {
    beacon: "UDP discovery beacon. Every 3 seconds each VanishDrop broadcasts its name, key fingerprint and ports so devices on the same Wi-Fi can find each other. Not encrypted and not trusted: identity is proved later in the TCP handshake.",
    alert: "Signed UDP delivery receipt. After saving a file, the receiver tells the sender over UDP. It's signed with RSA so it can't be faked. UDP may lose it, which is fine: the TCP reply already confirmed delivery.",
    HELLO: "Start of our VD1 handshake. Carries the sender's RSA public key, a fresh Diffie-Hellman public value and a random nonce, signed with RSA. Public values are safe to send in the open.",
    HELLO_REPLY: "The receiver's half of the handshake: its RSA key, its own Diffie-Hellman value and nonce, signed together with the sender's values so it can't be replayed elsewhere.",
    CONFIRM: "First encrypted frame. Proves the sender derived the same AES-256 session key and holds its RSA private key (signature over the whole handshake).",
    REQUEST: "Encrypted request: pair, offer a file (name, size, SHA-256, RSA signature) or a chat message.",
    REPLY: "Encrypted answer: accepted (with a resume offset), declined, or delivered.",
    CHUNK: "256 KB of the file, encrypted with AES-256-GCM. A counter nonce means any replayed, reordered or changed frame fails to decrypt.",
    CHUNK_PLAIN: "Lab demo mode: file bytes sent WITHOUT encryption, so you can read them in Wireshark. The receiver must allow this.",
    END: "Encrypted end-of-file marker. The receiver now checks the size and SHA-256 of the whole file.",
    ERROR: "A plain-text reason sent before closing the connection.",
    HTTP_IN: "A request from a browser to VanishDrop's web server (HTTP runs over TCP).",
    HTTP_OUT: "VanishDrop's response. For link uploads and downloads the body is AES-256 ciphertext made in the browser; the key after # in the link is never sent.",
    PCAP_TCP: "A raw TCP segment captured from the network adapter. Flags: S = SYN (open), A = ACK, P = PUSH (data), F = FIN (close), R = RESET. The 3-way handshake is S → SA → A.",
    PCAP_UDP: "A raw UDP datagram captured from the network adapter: no handshake, no acknowledgements.",
  };
  function explain(e) {
    if (e.proto === "pcap") return e.kind.startsWith("TCP") ? EXPLAIN.PCAP_TCP : EXPLAIN.PCAP_UDP;
    if (e.proto === "http") return e.dir === "in" ? EXPLAIN.HTTP_IN : EXPLAIN.HTTP_OUT;
    return EXPLAIN[e.kind] || "";
  }
  const clock = (t) => new Date(t * 1000).toLocaleTimeString([], { hour12: false }) + "." + String(Math.floor((t % 1) * 1000)).padStart(3, "0");

  function rowFor(e) {
    const tr = el("tr");
    tr.dataset.n = e.n;
    tr.append(el("td", "mono", clock(e.t)), el("td", null, e.proto.toUpperCase()),
      el("td", "dir " + e.dir, e.dir === "in" ? "←" : "→"),
      el("td", "what", e.kind + (e.note ? ` · ${e.note}` : "")), el("td", "mono peer", e.peer),
      el("td", "num mono", e.size.toLocaleString()),
      el("td", null, e.enc ? "Encrypted" : e.proto === "pcap" ? "" : "Plain"));
    if (e.enc) tr.lastChild.className = "enc"; else if (e.proto !== "pcap") tr.lastChild.className = "plain";
    tr.addEventListener("click", () => select(e, tr));
    return tr;
  }
  function select(e, tr) {
    selected = e.n;
    document.querySelectorAll("#rows tr.sel").forEach((r) => r.classList.remove("sel"));
    tr.classList.add("sel");
    $("d-empty").hidden = true; $("d-body").hidden = false;
    $("d-kv").replaceChildren(
      el("dt", null, "Protocol"), el("dd", null, e.proto.toUpperCase() + (e.src === "pcap" ? " (captured)" : "")),
      el("dt", null, "Type"), el("dd", null, e.kind),
      el("dt", null, "Direction"), el("dd", null, e.dir === "in" ? "Received" : "Sent"),
      el("dt", null, "Peer"), el("dd", "mono", e.peer || "—"),
      el("dt", null, "Size"), el("dd", null, `${e.size.toLocaleString()} bytes`),
      el("dt", null, "Encrypted"), el("dd", null, e.enc ? "Yes" : "No"),
      ...(e.note ? [el("dt", null, "Note"), el("dd", null, e.note)] : []));
    $("d-explain").textContent = explain(e);
    const hex = (e.head.match(/../g) || []);
    const ascii = hex.map((h) => { const c = parseInt(h, 16); return c >= 32 && c < 127 ? String.fromCharCode(c) : "."; }).join("");
    $("d-hex").textContent = hex.length ? hex.join(" ").replace(/(.{47}) /g, "$1\n") + "\n\n" + ascii : "(no payload)";
  }

  // New packets are added at the top; existing rows are never rebuilt, so clicks always land.
  function renderRows(newEvents, rebuild) {
    newEvents.forEach((e) => rows.unshift(e));
    rows.length = Math.min(rows.length, MAX_ROWS);
    const match = (e) => filter === "all" || e.proto === filter;
    const body = $("rows");
    if (rebuild) {
      body.replaceChildren(...rows.filter(match).slice(0, 200).map(rowFor));
    } else {
      const fresh = newEvents.filter(match);
      fresh.forEach((e) => body.insertBefore(rowFor(e), body.firstChild));   // oldest first, so the newest ends on top
      while (body.children.length > 200) body.lastChild.remove();
    }
    $("rows-empty").hidden = body.children.length > 0;
    if (selected) { const tr = body.querySelector(`tr[data-n="${selected}"]`); if (tr) tr.classList.add("sel"); }
  }

  function drawChart() {
    const c = $("chart"), ctx = c.getContext("2d");
    const w = c.clientWidth, h = c.height, dpr = window.devicePixelRatio || 1;
    c.width = w * dpr; c.height = h * dpr; c.style.height = h + "px"; ctx.scale(dpr, dpr);
    const s = data.series;
    const sum = (p) => s.map((x) => x[p + "_in"] + x[p + "_out"]);
    const lines = [["udp", "#00A884"], ["tcp", "#1F6BFF"], ["http", "#F2C14E"]].map(([p, col]) => [sum(p), col]);
    const max = Math.max(1024, ...lines.flatMap(([v]) => v));
    const top = Math.pow(2, Math.ceil(Math.log2(max)));
    const L = 56, R = 8, T = 8, B = 22, pw = w - L - R, ph = h - T - B;
    ctx.clearRect(0, 0, w, h);
    ctx.font = "11px 'Inter Tight', sans-serif"; ctx.fillStyle = "#8A8A8A"; ctx.strokeStyle = "#1F1F1F"; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = T + ph - (ph * i) / 4;
      ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(w - R, y); ctx.stroke();
      ctx.fillText(VD.bytes(Math.round((top * i) / 4)) + "/s", 0, y + 4);
    }
    ctx.fillText("60 s ago", L, h - 4); ctx.fillText("now", w - R - 22, h - 4);
    lines.forEach(([vals, col]) => {
      ctx.strokeStyle = col; ctx.lineWidth = 2; ctx.beginPath();
      vals.forEach((v, i) => { const x = L + (pw * i) / (vals.length - 1), y = T + ph - (ph * v) / top; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
      ctx.stroke();
    });
    const last5 = s.slice(-5), avg = (k) => last5.reduce((a, x) => a + x[k + "_in"] + x[k + "_out"], 0) / 5;
    $("rate-line").textContent = `Right now: UDP ${VD.bytes(Math.round(avg("udp")))}/s · TCP ${VD.bytes(Math.round(avg("tcp")))}/s · HTTP ${VD.bytes(Math.round(avg("http")))}/s`;
  }

  function renderStats() {
    $("c-udp").textContent = (data.counts.udp || 0).toLocaleString();
    $("c-tcp").textContent = (data.counts.tcp || 0).toLocaleString();
    $("c-http").textContent = (data.counts.http || 0).toLocaleString();
    let enc = 0, all = 0;
    rows.forEach((e) => { if (e.proto === "pcap") return; all += e.size; if (e.enc) enc += e.size; });
    $("c-enc").textContent = all ? Math.round((100 * enc) / all) + "%" : "–";
    const cap = data.capture;
    $("capture").checked = cap.running;
    $("capture").disabled = !cap.available;
    $("cap-status").textContent = !cap.available
      ? "Needs Scapy: run  py -m pip install scapy  and restart VanishDrop. On Windows it also needs Npcap, which comes with Wireshark."
      : cap.running ? `Capturing TCP ${data.ports.web}, TCP ${data.ports.tcp} and UDP ${data.ports.udp}. Filter by "Captured" to see raw packets.`
      : cap.error || "Off. Turn on to capture raw packets.";
  }

  async function tick() {
    if (paused) return;
    try {
      data = await VD.api("/api/monitor?after=" + after);
      let rebuild = false;
      if (data.seq < after) { rows.length = 0; rebuild = true; }   // monitor was cleared
      after = data.seq;
      renderRows(data.events, rebuild);
      renderStats(); drawChart();
    } catch (e) { /* server restarting */ }
  }

  document.querySelectorAll(".filter").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(".filter").forEach((x) => x.classList.toggle("active", x === b));
    filter = b.dataset.f; renderRows([], true);
  }));
  $("pause").addEventListener("click", () => { paused = !paused; $("pause").textContent = paused ? "Resume" : "Pause"; if (!paused) tick(); });
  $("clear").addEventListener("click", async () => { await VD.api("/api/monitor/clear", { method: "POST" }); rows.length = 0; renderRows([], true); after = 0; selected = null; $("d-body").hidden = true; $("d-empty").hidden = false; tick(); });
  $("capture").addEventListener("change", async (e) => {
    try { await VD.api("/api/monitor/capture", { json: { on: e.target.checked } }); }
    catch (ex) { e.target.checked = false; $("cap-status").textContent = ex.message; VD.toast(ex.message); }
    tick();
  });
  window.addEventListener("resize", () => data && drawChart());

  tick(); setInterval(tick, 1000);
})();
