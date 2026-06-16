// mbnt-read.mjs — a minimal, zero-dependency .mbnt (ZIP) reader.
//
// An .mbnt is a standard PKZIP archive (bundle-v1.md §2): root members
// canonical.json / proofs.json / manifest.json (and, for a disclosure
// bundle, manifest.json + linked_anchor/canonical.json). This reader uses
// ONLY Node stdlib — `node:zlib`'s inflateRawSync for DEFLATE (method 8)
// and a raw copy for STORE (method 0). NO JSZip, NO child_process / system
// `unzip`. It parses the End-Of-Central-Directory (EOCD) record, walks the
// central directory, and reads each local file header.
//
// The complementary writer is bundle.mjs's buildMbnt (STORE-only); this
// reader must round-trip whatever buildMbnt emits (asserted by the tests).
//
// PKZIP field offsets used below (all little-endian):
//   EOCD record (22 bytes, sig 0x06054b50):
//     +10 u16 total central-dir entry count
//     +12 u32 central-dir size
//     +16 u32 central-dir offset (from start of archive)
//   Central directory header (46 bytes, sig 0x02014b50):
//     +10 u16 compression method
//     +20 u32 compressed size
//     +24 u32 uncompressed size
//     +28 u16 file-name length
//     +30 u16 extra-field length
//     +32 u16 comment length
//     +42 u32 local-header offset
//     +46    file name bytes
//   Local file header (30 bytes, sig 0x04034b50):
//     +26 u16 file-name length
//     +28 u16 extra-field length
//     +30    file name bytes, then the (possibly compressed) data

import { inflateRawSync } from "node:zlib";

const SIG_EOCD = 0x06054b50;
const SIG_CDH = 0x02014b50;
const SIG_LFH = 0x04034b50;

/**
 * Reject entry names that could escape the extraction root via path
 * traversal. The notary's verifier had a known gap here; do not inherit
 * it. We forbid absolute paths, drive letters, and any `..` path segment.
 * @param {string} name
 */
function _assertSafeName(name) {
  if (name.length === 0) throw new Error("mbnt: empty entry name");
  const norm = name.replace(/\\/g, "/");
  if (norm.startsWith("/") || /^[a-zA-Z]:/.test(norm)) {
    throw new Error(`mbnt: unsafe absolute entry name: ${name}`);
  }
  for (const seg of norm.split("/")) {
    if (seg === "..") throw new Error(`mbnt: path-traversal entry name: ${name}`);
  }
}

/**
 * Read all members of a .mbnt zip into a { name: Uint8Array } map.
 * @param {Uint8Array} zipBytes
 * @returns {{ [name: string]: Uint8Array }}
 */
export function readMbntMembers(zipBytes) {
  const buf = Buffer.from(
    zipBytes.buffer,
    zipBytes.byteOffset,
    zipBytes.byteLength
  );

  // Locate the EOCD by scanning backward for its signature (the trailing
  // comment is length 0 in our bundles, but scan anyway for robustness).
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("mbnt: no EOCD record (not a zip?)");

  const cdCount = buf.readUInt16LE(eocd + 10);
  const cdOffset = buf.readUInt32LE(eocd + 16);

  const members = {};
  let p = cdOffset;
  for (let i = 0; i < cdCount; i++) {
    if (buf.readUInt32LE(p) !== SIG_CDH) {
      throw new Error(`mbnt: bad central-dir signature at entry ${i}`);
    }
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const lfhOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    _assertSafeName(name);

    // Walk into the local file header to find the data start (its own
    // name/extra lengths may differ from the central-dir record).
    if (buf.readUInt32LE(lfhOffset) !== SIG_LFH) {
      throw new Error(`mbnt: bad local-header signature for ${name}`);
    }
    const lfhNameLen = buf.readUInt16LE(lfhOffset + 26);
    const lfhExtraLen = buf.readUInt16LE(lfhOffset + 28);
    const dataStart = lfhOffset + 30 + lfhNameLen + lfhExtraLen;
    const compressed = buf.subarray(dataStart, dataStart + compSize);

    let data;
    if (method === 0) {
      // STORE — raw copy.
      data = Uint8Array.from(compressed);
    } else if (method === 8) {
      // DEFLATE — raw inflate (no zlib header).
      data = Uint8Array.from(inflateRawSync(compressed));
    } else {
      throw new Error(`mbnt: unsupported compression method ${method} for ${name}`);
    }
    members[name] = data;

    p += 46 + nameLen + extraLen + commentLen;
  }
  return members;
}
