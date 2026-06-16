// hex.mjs — lowercase-hex helpers for SHA-256 digests.
//
// Used by the disclosure-builder primitives (preimage.mjs, merkle.mjs,
// csv-row-v1.mjs). The disclosure-v1 spec pins lowercase hex on the
// wire (64 chars for SHA-256); this module is the byte<->hex boundary.
//
// Pure string/array manipulation; no browser API surface.

const HEX_CHARS = "0123456789abcdef";

/**
 * Convert a Uint8Array to a lowercase hex string.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    out += HEX_CHARS[b >>> 4] + HEX_CHARS[b & 0x0f];
  }
  return out;
}

/**
 * Decode a lowercase hex string to a Uint8Array.
 * @param {string} hex - even-length lowercase hex (^[0-9a-f]*$).
 * @returns {Uint8Array}
 * @throws {Error} on invalid input.
 */
export function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) {
    throw new Error("hexToBytes: input must be even-length lowercase hex");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const HEX64_RE = /^[0-9a-f]{64}$/;

/**
 * Validate a string matches ^[0-9a-f]{64}$.
 * @param {string} s
 * @returns {boolean}
 */
export function isHex64(s) {
  return typeof s === "string" && HEX64_RE.test(s);
}
