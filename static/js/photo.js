/* Photo privacy cleaner: finds and removes hidden details (GPS location, camera, date)
   from JPEG and PNG photos in the browser, before anything is encrypted or sent. */
(function () {
  "use strict";
  const { el } = VD;

  // ---------- EXIF (TIFF) reader: just the tags we report ----------
  function readTiff(view, start) {
    const le = view.getUint16(start) === 0x4949;
    const u16 = (o) => view.getUint16(start + o, le), u32 = (o) => view.getUint32(start + o, le);
    const out = {};
    function str(o, n) { let s = ""; for (let i = 0; i < n; i++) { const c = view.getUint8(start + o + i); if (!c) break; s += String.fromCharCode(c); } return s.trim(); }
    function rationals(o, n) { const a = []; for (let i = 0; i < n; i++) { const d = u32(o + 8 * i + 4); a.push(d ? u32(o + 8 * i) / d : 0); } return a; }
    function ifd(o, handler) {
      if (o <= 0 || start + o + 2 > view.byteLength) return;
      const n = u16(o);
      for (let i = 0; i < n && start + o + 2 + 12 * (i + 1) <= view.byteLength; i++) {
        const e = o + 2 + 12 * i, tag = u16(e), type = u16(e + 2), count = u32(e + 4);
        const size = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 }[type] || 1;
        const valOff = size * count > 4 ? u32(e + 8) : e + 8;
        handler(tag, type, count, valOff, e);
      }
    }
    try {
      ifd(u32(4), (tag, type, count, off, e) => {
        if (tag === 0x010f) out.make = str(off, count);
        else if (tag === 0x0110) out.model = str(off, count);
        else if (tag === 0x0112) out.orientation = u16(e + 8);
        else if (tag === 0x0132) out.date = str(off, count);
        else if (tag === 0x0131) out.software = str(off, count);
        else if (tag === 0x8769) ifd(u32(e + 8), (t2, ty2, c2, o2) => { if (t2 === 0x9003) out.date = str(o2, c2); });
        else if (tag === 0x8825) {
          const g = {};
          ifd(u32(e + 8), (t2, ty2, c2, o2, e2) => {
            if (t2 === 1) g.latRef = String.fromCharCode(view.getUint8(start + e2 + 8));
            else if (t2 === 2) g.lat = rationals(o2, 3);
            else if (t2 === 3) g.lonRef = String.fromCharCode(view.getUint8(start + e2 + 8));
            else if (t2 === 4) g.lon = rationals(o2, 3);
          });
          if (g.lat && g.lon) {
            const dms = (a) => a[0] + a[1] / 60 + a[2] / 3600;
            out.gps = { lat: dms(g.lat) * (g.latRef === "S" ? -1 : 1), lon: dms(g.lon) * (g.lonRef === "W" ? -1 : 1) };
          }
        }
      });
    } catch (e) { /* damaged EXIF: report what we have */ }
    return out;
  }

  // ---------- JPEG ----------
  const JPEG_DROP = new Set([0xe1, 0xec, 0xed, 0xfe]);   // APP1 EXIF/XMP, APP12, APP13 IPTC, COM
  function jpegSegments(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (view.getUint16(0) !== 0xffd8) return null;
    const segs = []; let p = 2;
    while (p + 4 <= bytes.length) {
      if (bytes[p] !== 0xff) return null;
      const marker = bytes[p + 1];
      if (marker === 0xda || marker === 0xd9) { segs.push({ marker, start: p, end: bytes.length, tail: true }); break; }
      const len = view.getUint16(p + 2);
      segs.push({ marker, start: p, end: p + 2 + len });
      p += 2 + len;
    }
    return { view, segs };
  }
  function inspectJpeg(bytes) {
    const parsed = jpegSegments(bytes);
    if (!parsed) return null;
    const info = { kind: "jpeg", found: [] };
    for (const s of parsed.segs) {
      if (s.marker === 0xe1 && String.fromCharCode(...bytes.slice(s.start + 4, s.start + 8)) === "Exif") {
        Object.assign(info, readTiff(parsed.view, s.start + 10));
        info.found.push("EXIF");
      } else if (s.marker === 0xe1) info.found.push("XMP");
      else if (s.marker === 0xed) info.found.push("IPTC");
      else if (s.marker === 0xfe) info.found.push("Comment");
    }
    return info;
  }
  function stripJpeg(bytes) {
    const parsed = jpegSegments(bytes);
    const parts = [bytes.slice(0, 2)];
    for (const s of parsed.segs) if (!JPEG_DROP.has(s.marker)) parts.push(bytes.slice(s.start, s.end));
    return new Blob(parts, { type: "image/jpeg" });
  }

  // ---------- PNG ----------
  const PNG_SIG = [137, 80, 78, 71, 13, 10, 26, 10];
  const PNG_DROP = new Set(["tEXt", "iTXt", "zTXt", "eXIf", "tIME"]);
  function pngChunks(bytes) {
    if (!PNG_SIG.every((b, i) => bytes[i] === b)) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const chunks = []; let p = 8;
    while (p + 12 <= bytes.length) {
      const len = view.getUint32(p), type = String.fromCharCode(...bytes.slice(p + 4, p + 8));
      chunks.push({ type, start: p, end: p + 12 + len, data: p + 8, len });
      p += 12 + len;
      if (type === "IEND") break;
    }
    return { view, chunks };
  }
  function inspectPng(bytes) {
    const parsed = pngChunks(bytes);
    if (!parsed) return null;
    const info = { kind: "png", found: [] };
    for (const c of parsed.chunks) {
      if (c.type === "eXIf") { Object.assign(info, readTiff(parsed.view, c.data)); info.found.push("EXIF"); }
      else if (PNG_DROP.has(c.type)) {
        const key = String.fromCharCode(...bytes.slice(c.data, Math.min(c.data + 40, c.end - 4))).split("\0")[0];
        info.found.push(c.type === "tIME" ? "Edit time" : `Text "${key}"`);
      }
    }
    return info;
  }
  function stripPng(bytes) {
    const parsed = pngChunks(bytes);
    const parts = [bytes.slice(0, 8)];
    for (const c of parsed.chunks) if (!PNG_DROP.has(c.type)) parts.push(bytes.slice(c.start, c.end));
    return new Blob(parts, { type: "image/png" });
  }

  // ---------- public API ----------
  async function inspect(file) {
    if (!file || !/^image\/(jpeg|png)$/.test(file.type) && !/\.(jpe?g|png)$/i.test(file.name || "")) return { supported: false };
    const bytes = new Uint8Array(await file.arrayBuffer());
    const info = inspectJpeg(bytes) || inspectPng(bytes);
    if (!info) return { supported: false };
    info.supported = true;
    info.hasDetails = info.found.length > 0;
    return info;
  }
  async function reencode(file, type) {
    // Rotated photos: draw them upright, so removing the orientation tag doesn't turn them sideways.
    const bmp = await createImageBitmap(file, { imageOrientation: "from-image" });
    const c = document.createElement("canvas"); c.width = bmp.width; c.height = bmp.height;
    c.getContext("2d").drawImage(bmp, 0, 0);
    return new Promise((res) => c.toBlob(res, type, 0.92));
  }
  async function clean(file) {
    const info = await inspect(file);
    if (!info.supported || !info.hasDetails) return { file, removed: [] };
    let blob;
    if (info.kind === "jpeg" && info.orientation && info.orientation !== 1) blob = await reencode(file, "image/jpeg");
    else {
      const bytes = new Uint8Array(await file.arrayBuffer());
      blob = info.kind === "jpeg" ? stripJpeg(bytes) : stripPng(bytes);
    }
    return { file: new File([blob], file.name, { type: file.type || blob.type, lastModified: Date.now() }), removed: info.found };
  }
  function describe(info) {
    const items = [];
    if (info.gps) items.push(["Location", `${info.gps.lat.toFixed(5)}, ${info.gps.lon.toFixed(5)}`, true]);
    if (info.make || info.model) items.push(["Camera", [info.make, info.model].filter(Boolean).join(" ")]);
    if (info.date) items.push(["Taken", info.date]);
    if (info.software) items.push(["Edited with", info.software]);
    const other = info.found.filter((f) => f !== "EXIF");
    if (other.length) items.push(["Other", other.join(", ")]);
    if (!items.length && info.found.length) items.push(["Other", info.found.join(", ")]);
    return items;
  }

  // Shows what a photo reveals and a switch to remove it. Returns a function: should we clean?
  async function attach(file, box) {
    box.replaceChildren(); box.hidden = true;
    const info = await inspect(file).catch(() => ({ supported: false }));
    if (!info.supported) return () => false;
    box.hidden = false;
    box.className = "privacy " + (info.hasDetails ? (info.gps ? "danger" : "warn") : "ok");
    if (!info.hasDetails) { box.appendChild(el("p", null, "No hidden location or camera details in this photo.")); return () => false; }
    box.appendChild(el("strong", null, info.gps ? "This photo reveals where it was taken" : "This photo has hidden details"));
    const dl = el("dl", "kv");
    describe(info).forEach(([k, v]) => dl.append(el("dt", null, k), el("dd", null, v)));
    box.appendChild(dl);
    const label = el("label", "switch");
    const input = el("input"); input.type = "checkbox"; input.checked = true;
    label.append(input, el("span", "switch-track"), el("span", null, "Remove hidden details before sending"));
    box.appendChild(label);
    return () => input.checked;
  }

  VD.photo = { inspect, clean, attach };
})();
