// bundle.mjs — STORE-only PKZIP envelope for .mbnt bundles.
//
// Per docs/notary_spec/bundle-v1.md §2, an .mbnt is a standard PKZIP
// (deflate or store) ZIP containing manifest.json + canonical.json (and
// optionally proofs.json) at the root. The Builder produces a
// disclosure-style .mbnt whose manifest.json carries the disclosure
// block (0021 + disclosure-v1.md §3) and whose canonical.json is the
// linked-anchor carrier doc bytes.
//
// uses STORE-only compression (legal per bundle-v1.md §2):
// the bundles are < 5 KB so compression buys nothing, STORE keeps the
// audit surface ~150 lines, and we avoid the CompressionStream / jszip
// dependency. EOCD comment length is 0 per bundle-v1.md §2.2.

let _crc32Table = null;
function _ensureCrc32Table() {
  if (_crc32Table !== null) return;
  _crc32Table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    _crc32Table[i] = c >>> 0;
  }
}

function crc32(bytes) {
  _ensureCrc32Table();
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    c = _crc32Table[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function _u16(view, offset, value) {
  view.setUint16(offset, value, true);
}
function _u32(view, offset, value) {
  view.setUint32(offset, value, true);
}

function _writeLfh(filename, data) {
  const nameBytes = new TextEncoder().encode(filename);
  const out = new Uint8Array(30 + nameBytes.length);
  const view = new DataView(out.buffer);
  _u32(view, 0, 0x04034b50);
  _u16(view, 4, 10); // version needed (1.0 for STORE)
  _u16(view, 6, 0); // general purpose flags
  _u16(view, 8, 0); // compression method = STORE
  _u16(view, 10, 0); // mod time
  _u16(view, 12, 0x0021); // mod date = 1980-01-01
  _u32(view, 14, crc32(data));
  _u32(view, 18, data.length); // compressed size
  _u32(view, 22, data.length); // uncompressed size
  _u16(view, 26, nameBytes.length);
  _u16(view, 28, 0); // extra field length
  out.set(nameBytes, 30);
  return out;
}

function _writeCdh(filename, data, lfhOffset) {
  const nameBytes = new TextEncoder().encode(filename);
  const out = new Uint8Array(46 + nameBytes.length);
  const view = new DataView(out.buffer);
  _u32(view, 0, 0x02014b50);
  _u16(view, 4, 10); // version made by
  _u16(view, 6, 10); // version needed
  _u16(view, 8, 0);
  _u16(view, 10, 0); // compression method
  _u16(view, 12, 0); // mod time
  _u16(view, 14, 0x0021); // mod date
  _u32(view, 16, crc32(data));
  _u32(view, 20, data.length);
  _u32(view, 24, data.length);
  _u16(view, 28, nameBytes.length);
  _u16(view, 30, 0); // extra
  _u16(view, 32, 0); // comment
  _u16(view, 34, 0); // disk number
  _u16(view, 36, 0); // internal attrs
  _u32(view, 38, 0); // external attrs
  _u32(view, 42, lfhOffset);
  out.set(nameBytes, 46);
  return out;
}

function _writeEocd(cdhCount, cdhSize, cdhOffset) {
  const out = new Uint8Array(22);
  const view = new DataView(out.buffer);
  _u32(view, 0, 0x06054b50);
  _u16(view, 4, 0); // disk number
  _u16(view, 6, 0); // disk where CD starts
  _u16(view, 8, cdhCount);
  _u16(view, 10, cdhCount);
  _u32(view, 12, cdhSize);
  _u32(view, 16, cdhOffset);
  _u16(view, 20, 0); // EOCD comment length MUST be 0 per bundle-v1.md §2.2
  return out;
}

/**
 * Build a .mbnt zip containing the named entries (STORE compression).
 *
 * The linked-anchor carrier doc is emitted at the nested entry name
 * `linked_anchor/canonical.json` — the canonical spec path per
 * disclosure-v1.md §4 (the carrier is `linked_anchor.canonical`). A
 * nested entry name is just a forward-slash-containing filename in the
 * zip; `_writeLfh`/`_writeCdh` TextEncode arbitrary names, so the
 * existing CRC/LFH/CDH framing, STORE-only compression, the 1980
 * mod-date, and the EOCD-comment-length-0 invariant all carry over
 * unchanged.
 *
 * A zip-root `canonical.json` is written only when `entries.canonical`
 * is supplied. Disclosure bundles pass it absent: per disclosure-v1.md
 * §2 the root canonical.json would be the disclosure's OWN (T2) doc,
 * which does not exist for an unanchored handoff, so the carrier lives
 * solely at the nested spec path and `locateCarrier` reads it there.
 * (The earlier 0027 §2 transitional root dup was dropped once the
 * verifier's `unpackBundle` null-guarded its root canonical.json read.)
 *
 * @param {{manifest: Uint8Array, canonical?: Uint8Array,
 *          linkedAnchorCanonical?: Uint8Array, proofs?: Uint8Array}} entries
 * @returns {Uint8Array} the zip bytes
 */
export function buildMbnt(entries) {
  const entryList = [];
  entryList.push(["manifest.json", entries.manifest]);
  if (entries.canonical) entryList.push(["canonical.json", entries.canonical]);
  if (entries.linkedAnchorCanonical) {
    entryList.push([
      "linked_anchor/canonical.json",
      entries.linkedAnchorCanonical,
    ]);
  }
  if (entries.proofs) entryList.push(["proofs.json", entries.proofs]);

  const parts = [];
  const lfhOffsets = [];
  let cursor = 0;
  for (const [name, data] of entryList) {
    lfhOffsets.push(cursor);
    const lfh = _writeLfh(name, data);
    parts.push(lfh);
    cursor += lfh.length;
    parts.push(data);
    cursor += data.length;
  }
  const cdhStart = cursor;
  for (let i = 0; i < entryList.length; i++) {
    const [name, data] = entryList[i];
    const cdh = _writeCdh(name, data, lfhOffsets[i]);
    parts.push(cdh);
    cursor += cdh.length;
  }
  const cdhSize = cursor - cdhStart;
  parts.push(_writeEocd(entryList.length, cdhSize, cdhStart));

  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

const _SIG_EOCD = 0x06054b50;
const _SIG_CDH = 0x02014b50;

/**
 * Enumerate the member (file) names of an .mbnt zip by walking the central
 * directory. Pure — no node/JSZip dependency — so it runs in the browser
 * builder and node alike; it mirrors the framing `buildMbnt` writes (STORE,
 * 1980 mod-date, EOCD comment-length 0). The complementary node reader is
 * packages/disclosure-redact/mbnt-read.mjs, but that one pulls in
 * node:zlib; this returns names only, which is all the emitted-member
 * allowlist assertion (disclosure-pack.mjs) needs.
 *
 * @param {Uint8Array} zipBytes
 * @returns {string[]} member names in central-directory order
 */
export function mbntMemberNames(zipBytes) {
  if (!(zipBytes instanceof Uint8Array) || zipBytes.length < 22) {
    throw new Error("mbnt: not a zip (too short)");
  }
  const dv = new DataView(
    zipBytes.buffer, zipBytes.byteOffset, zipBytes.byteLength
  );
  // EOCD is the last record; scan back for its signature (our writer emits
  // comment-length 0, so it lands at length-22, but a backward scan stays
  // correct if a trailing comment is ever present).
  let eocd = -1;
  for (let i = zipBytes.length - 22; i >= 0; i--) {
    if (dv.getUint32(i, true) === _SIG_EOCD) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("mbnt: no EOCD record (not a zip?)");
  const count = dv.getUint16(eocd + 10, true);
  let off = dv.getUint32(eocd + 16, true);
  const names = [];
  const dec = new TextDecoder();
  for (let n = 0; n < count; n++) {
    if (off + 46 > zipBytes.length
        || dv.getUint32(off, true) !== _SIG_CDH) {
      throw new Error("mbnt: bad central-directory header");
    }
    const nameLen = dv.getUint16(off + 28, true);
    const extraLen = dv.getUint16(off + 30, true);
    const commentLen = dv.getUint16(off + 32, true);
    names.push(dec.decode(zipBytes.subarray(off + 46, off + 46 + nameLen)));
    off += 46 + nameLen + extraLen + commentLen;
  }
  return names;
}

/**
 * Trigger a browser download of a Uint8Array as a named file.
 *
 * @param {Uint8Array} bytes
 * @param {string} filename
 */
export function downloadBlob(bytes, filename) {
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
