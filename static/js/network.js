(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const { el } = VD;
  let tool = null, info = null;

  const EXPLAIN = {
    ipconfig: [
      "Find your Wi-Fi adapter. IPv4 Address is this laptop's address on the network: it's what other devices use to reach VanishDrop.",
      "Subnet Mask (often 255.255.255.0) says which addresses are on the same network. Devices on the same subnet talk directly through the switch.",
      "Default Gateway is your router. DNS Servers turn names like google.com into IP addresses.",
    ],
    ping: [
      "ping sends ICMP Echo Request packets and waits for Echo Replies.",
      "time= is the round-trip time (RTT) in milliseconds. On home Wi-Fi to your router expect 1–10 ms; to a website 20–100 ms.",
      "Lost packets or 'Request timed out' means the device is off, blocking ping (Windows Firewall does by default), or the network is dropping packets.",
    ],
    traceroute: [
      "Each line is one router (hop) between you and the target. The first hop is your gateway.",
      "It works by sending packets with TTL 1, 2, 3… Each router that drops a packet because its TTL ran out sends back an ICMP 'time exceeded' message, revealing itself.",
      "* * * means that router doesn't answer these messages. That's normal for many routers.",
    ],
    nslookup: [
      "Server is the DNS server your laptop asked (usually your router or your ISP).",
      "Name / Address is the answer: the IP address(es) for that name. 'Non-authoritative answer' means it came from a cache, not the domain's own DNS server.",
      "DNS normally uses UDP port 53, and it isn't encrypted: you can see these lookups in Wireshark with the filter dns.",
    ],
    netstat: [
      "Lists open network ports. VanishDrop listens on its web port (TCP), its discovery port (UDP) and its transfer port (TCP).",
      "LISTENING / LISTEN means waiting for connections. ESTABLISHED means a live TCP connection, for example a transfer in progress.",
      "0.0.0.0 means 'all network adapters': VanishDrop accepts connections from your Wi-Fi as well as from this laptop.",
    ],
    arp: [
      "ARP maps IP addresses to MAC (hardware) addresses on your local network.",
      "Your gateway's IP appears with its MAC address: that's your router. Other entries are devices your laptop recently talked to, such as a laptop you sent files to.",
      "Switches forward frames using these MAC addresses, not IP addresses.",
    ],
    route: [
      "The routing table: for each destination network, which gateway and adapter to use.",
      "The 0.0.0.0/0 (default) route points to your gateway: anything not on your own network goes to the router.",
      "The route for your own subnet has no gateway (On-link): those devices are reached directly.",
    ],
  };

  async function loadInfo() {
    try {
      info = await VD.api("/api/netcheck/info");
      document.querySelectorAll(".tool-name").forEach((n) => (n.textContent = info.windows ? n.dataset.win : n.dataset.nix));
      $("net-kv").replaceChildren(
        el("dt", null, "This laptop"), el("dd", "mono", info.ip),
        el("dt", null, "Gateway"), el("dd", "mono", info.gateway || "not found"),
        el("dt", null, "Web"), el("dd", "mono", `TCP ${info.ports.web}`),
        el("dt", null, "Discovery"), el("dd", "mono", `UDP ${info.ports.udp}`),
        el("dt", null, "Transfers"), el("dd", "mono", `TCP ${info.ports.tcp}`),
        el("dt", null, "Nearby"), el("dd", null, info.peers.length ? info.peers.map((p) => `${p.name} (${p.ip})`).join(", ") : "none right now"));
    } catch (e) { /* ignore */ }
  }

  function quickTargets() {
    const box = $("quick-targets"); box.replaceChildren();
    const opts = [];
    if (info && info.gateway) opts.push(["Your router", info.gateway]);
    (info ? info.peers : []).forEach((p) => opts.push([p.name, p.ip]));
    opts.push(["google.com", "google.com"], ["Google DNS", "8.8.8.8"]);
    opts.forEach(([label, value]) => {
      const b = el("button", "tag tag-btn", label); b.type = "button";
      b.addEventListener("click", () => { $("target").value = value; $("nc-error").hidden = true; });
      box.appendChild(b);
    });
    box.hidden = false;
  }

  document.querySelectorAll(".tool").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(".tool").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    tool = b.dataset.tool;
    const needs = !!b.dataset.needsTarget;
    $("target-field").hidden = !needs;
    if (needs) { quickTargets(); $("target").focus(); } else $("quick-targets").hidden = true;
    $("run").disabled = false;
    $("run").textContent = `Run ${b.querySelector(".tool-name").textContent}`;
    $("nc-error").hidden = true;
  }));

  $("target").addEventListener("keydown", (e) => { if (e.key === "Enter") $("run").click(); });
  $("run").addEventListener("click", async () => {
    if (!tool) return;
    const target = $("target").value.trim();
    const err = (m) => { $("nc-error").textContent = m; $("nc-error").hidden = false; };
    $("nc-error").hidden = true;
    if (!$("target-field").hidden && !target) return err("Enter a host name or IP address first.");
    const label = $("run").textContent;
    $("run").disabled = true; $("run").textContent = "Running… (tracert can take up to a minute)";
    try {
      const r = await VD.api("/api/netcheck", { json: { tool, target } });
      $("out-card").hidden = false;
      $("out-title").textContent = r.command;
      $("out-meta").textContent = `${r.seconds}s · exit ${r.code}`;
      $("output").textContent = r.output || "(no output)";
      $("explain").replaceChildren(el("h3", null, "What this shows"), ...EXPLAIN[tool].map((t) => el("p", "muted", t)));
      $("out-card").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) { err(e.message); }
    finally { $("run").disabled = false; $("run").textContent = label; }
  });

  loadInfo();
})();
