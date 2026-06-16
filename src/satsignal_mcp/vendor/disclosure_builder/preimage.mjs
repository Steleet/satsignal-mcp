// preimage.mjs — shared leaf-hash preimage builder.
//
// Byte-for-byte port of src/satsignal_notary/disclosure/preimage.py.
// Used by csv-row-v1.mjs and will be used unchanged by
// json-field-v1.mjs and text-paragraph-sentence-v1.mjs
//.
//
// Byte layout (forever-pinned per docs/notary_spec/disclosure-v1.md):
//
//     profile_literal.encode("utf-8")
//     || 0x00
//     || leaf_id.encode("utf-8")
//     || 0x00
//     || value_bytes
//     || 0x00
//     || salt_bytes

import { bytesToHex } from "./hex.mjs";

const ZERO = new Uint8Array([0x00]);

function concatBytes(...parts) {
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

/**
 * Construct the shared leaf-hash preimage.
 *
 * @param {string} profileLiteral - e.g. "satsignal.csv.row.v1"
 * @param {string} leafId - e.g. "r000000"
 * @param {Uint8Array} valueBytes - profile-specific encoded bytes
 * @param {Uint8Array} saltBytes - raw bytes (typically 16)
 * @returns {Uint8Array}
 */
export function buildPreimage(profileLiteral, leafId, valueBytes, saltBytes) {
  const enc = new TextEncoder();
  return concatBytes(
    enc.encode(profileLiteral),
    ZERO,
    enc.encode(leafId),
    ZERO,
    valueBytes,
    ZERO,
    saltBytes,
  );
}

/**
 * Compute sha256(buildPreimage(...)) and return 64-char lowercase hex.
 *
 * @param {string} profileLiteral
 * @param {string} leafId
 * @param {Uint8Array} valueBytes
 * @param {Uint8Array} saltBytes
 * @returns {Promise<string>}
 */
export async function hashLeaf(profileLiteral, leafId, valueBytes, saltBytes) {
  const preimage = buildPreimage(profileLiteral, leafId, valueBytes, saltBytes);
  const digest = await crypto.subtle.digest("SHA-256", preimage);
  return bytesToHex(new Uint8Array(digest));
}
