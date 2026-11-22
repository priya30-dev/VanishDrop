(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const { el } = VD;

  function dump(hex) {
    const lines = [];
    for (let off = 0; off < hex.length / 2; off += 16) {
      const pairs = hex.slice(off * 2, off * 2 + 32).match(/../g) || [];
      const ascii = pairs.map((p) => { const c = parseInt(p, 16); return c >= 32 && c < 127 ? String.fromCharCode(c) : "."; }).join("");
      lines.push(off.toString(16).padStart(6, "0") + "  " + pairs.join(" ").padEnd(47, " ") + "  " + ascii);
    }
    return lines.join("\n");
  }
  function card(kind, row, extra) {
    const c = el("article", "card vault-item");
    const kv = el("dl", "kv");
    const add = (k, v) => { kv.append(el("dt", null, k), el("dd", null, v)); };
    add("Type", kind); add("Stored as", row.id + ".bin"); add("Size", VD.bytes(row.size)); add(extra[0], extra[1]);
    c.appendChild(kv);
    c.appendChild(el("pre", "hexdump", dump(row.head)));
    return c;
  }
  async function load() {
    const r = await VD.api("/api/server-view");
    const cards = [
      ...r.links.map((l) => card(l.kind === "note" ? "Secret note" : "Shared file" + (l.password ? " (password)" : ""), l, ["File name as stored", l.enc_meta.slice(0, 40) + "…"])),
      ...r.uploads.map((u) => card("Upload request file", u, ["Key as stored (RSA-wrapped)", u.wrapped_key.slice(0, 40) + "…"])),
    ];
    $("vault").replaceChildren(...cards);
    $("vault-empty").hidden = cards.length > 0;
  }
  $("refresh").addEventListener("click", load);
  load();
})();
