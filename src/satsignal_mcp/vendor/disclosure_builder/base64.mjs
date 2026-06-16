// base64.mjs — base64 helpers for the Disclosure Builder.
//
// Uses the platform's atob/btoa (built-in on both browsers and Node 18+
// on globalThis). The Latin-1 string detour is the textbook binary-safe
// idiom; the corpus compares decoded bytes, not character-by-character
// base64 strings.

/**
 * Encode a Uint8Array as a base64 string (RFC 4648 with `=` padding).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

/**
 * Decode a base64 string to a Uint8Array.
 * @param {string} b64
 * @returns {Uint8Array}
 * @throws {Error} on invalid base64.
 */
export function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}
