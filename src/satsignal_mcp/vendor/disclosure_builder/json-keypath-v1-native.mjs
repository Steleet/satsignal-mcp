// json-keypath-v1-native.mjs — the NATIVE (unsalted/sealed,
// objects-only, sorted-top-level-key, duplicate-last) json-keypath-v1
// leaf rule the redact-from-original tool binds to (0031).
//
// This is the disclosure-side port of the per-top-level-key merkle EVERY
// JSON anchor already commits. It is byte-for-byte the canon + leaf rule
// in src/satsignal_notary/web/templates.py:
//   - standard: `jcsCanonicalize` + `buildJsonProofs` (~2139/~2159):
//     parse → sort top-level keys → per-key entry =
//     JSON.stringify(k.normalize('NFC')) + ':' + jcsCanonicalize(value);
//     leaf = sha256(utf8(entry)); duplicate-last merkle;
//   - sealed: `jcs`/`buildJsonCanonical` (~5801/~5819) feeding the
//     GENERIC sealed merkle assembly — the SAME sorted-key entry strings,
//     per-leaf HKDF salt + HMAC over each entry.
// Ground truth: docs/notary_spec/profiles/json-keypath-v1.md.
//
// Sibling of csv-row-v1-native.mjs (0029) and text-line-v1-native.mjs
// (0030). KEY DIFFERENCES vs text-line-v1:
//   - canon = JSON JCS re-serialization (RFC-8785-ish: parse → recursive
//     sorted-key, whitespace-free re-emit), NOT a BOM/NFC/line-ending
//     text normalize. JSON.parse handles the input; jcsCanonicalize emits
//     the canonical form. There is NO text-style `normalize…` step.
//   - segmentation = OBJECTS ONLY. The leaf-set exists only when the top
//     level is a JSON object (not an array, scalar, null, or parse-error)
//     with ≥1 key. Each leaf = one TOP-LEVEL KEY, in sorted-key order.
//   - the leaf "value" is the per-key ENTRY STRING (key + ':' + canonical
//     value); the KEY is embedded IN the value, so revealed[i].value
//     carries the whole entry. A leaf index is the SORTED-key index.
//   - NO header concept (headerRow always null), same as text-line-v1.
// SHARED with csv-row-v1 / text-line-v1: bare sha256(utf8(value))
// standard leaf, the per-leaf HKDF/HMAC sealed leaf (the anchor's sealed
// merkle assembly is generic across file types), and duplicate-last-on-
// odd merkle.
//
// Pure: no DOM, no jszip. The browser glue (app.mjs) handles file I/O,
// unzip, and DOM; this module + the redact core are node-testable.

import { bytesToHex } from "./hex.mjs";

const _LEAF_ID_MAX_KEYS = 1_000_000;

/**
 * Thrown when native json-keypath-v1 canonicalization yields no leaves
 * (top level is not an object, or is an empty object, or the bytes are
 * not valid JSON). The message carries a spec-pinned reason.
 */
export class InvalidNativeJsonInput extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidNativeJsonInput";
  }
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

// ── SEALED-mode primitives (json-keypath-v1.md §5b / 0031) ───────────
// Byte-for-byte mirror of the anchor (web/templates.py deriveLeafSalt /
// hmacSha256). IDENTICAL to csv-row-v1-native.mjs and
// text-line-v1-native.mjs's sealed primitives — the anchor's sealed
// per-leaf HKDF/HMAC derivation is generic across file types (the same
// `deriveLeafSalt`/`hmacSha256` feed every merkleScheme). Kept self-
// contained here (the sibling modules' copies stay byte-untouched) so
// each native profile is an independent port of its anchor rule.
const _SEALED_HKDF_SALT = new TextEncoder().encode(
  "satsignal-sealed-v1/per-leaf"
);
const _SEALED_HKDF_INFO_PREFIX = new TextEncoder().encode("chunk/");
export const SEALED_ALGO = "merkle-hmac-sha256";
export const SEALED_SALT_VERSION = "salt_v1";
const _SEALED_MASTER_SALT_LEN = 32;

/**
 * HKDF-SHA256(ikm, salt, info, L) -> raw bytes. Mirrors the anchor's
 * `hkdf` (crypto.subtle deriveBits over an imported HKDF key).
 * @param {Uint8Array} ikm
 * @param {Uint8Array} salt
 * @param {Uint8Array} info
 * @param {number} length - output length in bytes
 * @returns {Promise<Uint8Array>}
 */
async function _hkdfSha256(ikm, salt, info, length) {
  const key = await crypto.subtle.importKey(
    "raw",
    ikm,
    { name: "HKDF" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}

/**
 * Per-leaf salt for sealed leaf index `i`. Byte-parity twin of
 * `deriveLeafSalt` (web/templates.py:5688):
 *   salt_i = HKDF-SHA256(ikm=master, salt="satsignal-sealed-v1/per-leaf",
 *            info="chunk/" || u32_be(i), L=32).
 * The `info` counter is BIG-ENDIAN u32 (DataView setUint32(..., false)).
 * @param {Uint8Array} masterSaltBytes - the 32-byte master salt (IKM).
 * @param {number} leafIndex - zero-based sorted-key index.
 * @returns {Promise<Uint8Array>} the 32-byte per-leaf salt.
 */
export async function deriveLeafSalt(masterSaltBytes, leafIndex) {
  const idx = new Uint8Array(4);
  new DataView(idx.buffer).setUint32(0, leafIndex, false); // u32 BIG-ENDIAN
  const info = new Uint8Array(_SEALED_HKDF_INFO_PREFIX.length + 4);
  info.set(_SEALED_HKDF_INFO_PREFIX, 0);
  info.set(idx, _SEALED_HKDF_INFO_PREFIX.length);
  return await _hkdfSha256(masterSaltBytes, _SEALED_HKDF_SALT, info, 32);
}

/**
 * HMAC-SHA256(key, msg) -> lowercase hex. The SEALED leaf
 * (json-keypath-v1.md §5b): leaf = HMAC-SHA256(per-leaf salt,
 * utf8(entry)). Byte-parity twin of `hmacSha256` (web/templates.py:5669).
 * @param {Uint8Array} keyBytes - the per-leaf salt.
 * @param {Uint8Array} msgBytes - utf8(canonical_entry).
 * @returns {Promise<string>} 64-char lowercase hex.
 */
async function _hmacSha256Hex(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  return bytesToHex(new Uint8Array(sig));
}

/**
 * JCS (RFC-8785-ish) canonicalizer — VERBATIM port of `jcsCanonicalize`
 * (web/templates.py:2139) / `jcs` (web/templates.py:5801), byte-identical
 * in both anchor branches: recursive, sorted object keys, no whitespace,
 * NFC-normalized strings/keys, NaN/Infinity rejected, numbers via the ES
 * Number.prototype.toString. Exported so the drop-key renderer reuses
 * the SAME canon as the anchor (any divergence would break the bind).
 * @param {*} value - a parsed JSON value.
 * @returns {string} the canonical serialization.
 */
export function jcsCanonicalize(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("JSON canonical: NaN/Infinity not allowed");
    }
    return String(value);
  }
  if (typeof value === "string") return JSON.stringify(value.normalize("NFC"));
  if (Array.isArray(value)) {
    return "[" + value.map(jcsCanonicalize).join(",") + "]";
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return (
      "{" +
      keys
        .map(
          (k) =>
            JSON.stringify(k.normalize("NFC")) +
            ":" +
            jcsCanonicalize(value[k])
        )
        .join(",") +
      "}"
    );
  }
  throw new Error("JSON canonical: unsupported type " + typeof value);
}

/**
 * Given a PARSED top-level JSON object, return its sorted top-level key
 * list and the per-key entry strings (in the SAME sorted order), where
 * each entry =
 *   JSON.stringify(k.normalize('NFC')) + ':' + jcsCanonicalize(parsed[k]).
 * THIS STRING is the leaf "value" — it is what sha256(utf8(...)) hashes
 * and what a disclosure's revealed[i].value carries; the key is embedded
 * IN the entry. Exported so the renderer builds entries identically.
 *
 * Does NOT parse, decode, or validate object-ness — the caller has
 * already established `parsed` is a non-array object (see _canonicalKeys).
 * @param {Object} parsed - a parsed, non-array JSON object.
 * @returns {{keys: string[], entries: string[]}}
 */
export function keyEntries(parsed) {
  const keys = Object.keys(parsed).sort();
  const entries = keys.map(
    (k) =>
      JSON.stringify(k.normalize("NFC")) + ":" + jcsCanonicalize(parsed[k])
  );
  return { keys, entries };
}

/**
 * leaf_id = "k" + 6-digit zero-padded leaf index (the SORTED-key index,
 * NOT a source-file key position). Display / ordering handle only — NOT
 * part of any hash preimage (json-keypath-v1.md §3). Distinct prefix from
 * csv-row-v1's "r" and text-line-v1's "l" for human readability only.
 * @param {number} leafIndex
 * @returns {string}
 */
export function encodeLeafId(leafIndex) {
  if (!Number.isInteger(leafIndex) || leafIndex < 0) {
    throw new Error(`encodeLeafId: bad index ${leafIndex}`);
  }
  if (leafIndex >= _LEAF_ID_MAX_KEYS) {
    throw new Error(`encodeLeafId: index ${leafIndex} >= ${_LEAF_ID_MAX_KEYS}`);
  }
  return "k" + String(leafIndex).padStart(6, "0");
}

/**
 * Shared canon + segmentation: decode -> parse -> objects-only gate ->
 * sorted-key entries -> validity caps. The SAME segmentation both modes
 * use (json-keypath-v1.md §2/§3): standard (§4) and sealed (§5b) differ
 * ONLY in the per-leaf hash, never in segmentation.
 *
 * @param {Uint8Array} fileBytes
 * @returns {{headerRow: null, keys: string[], entries: string[]}}
 *   headerRow is ALWAYS null (json-keypath-v1 has no header; the field is
 *   present only to keep the {headerRow, dataRows} shape the redact core
 *   shares across native profiles).
 * @throws {InvalidNativeJsonInput} when the bytes are not valid JSON, the
 *   top level is not an object, or the object has zero keys.
 */
function _canonicalKeys(fileBytes) {
  // Lenient UTF-8 decode (U+FFFD on invalid bytes) — MATCHES the anchor's
  // `file.text()`, which decodes leniently. A file the anchor accepted
  // (committing leaves over its parse of the U+FFFD-replaced text) must
  // recompute to the SAME leaves here, not be rejected; recompute-
  // mismatch then stays the single, distinct "wrong file/bundle" failure
  // path.
  const text = new TextDecoder("utf-8").decode(fileBytes);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new InvalidNativeJsonInput(
      "invalid_json_parse: file is not valid JSON and is not a valid " +
        "json-keypath-v1 disclosure source (json-keypath-v1.md §3)"
    );
  }
  // OBJECTS ONLY — the per-key merkle leaf-set exists only for a top-level
  // JSON object. Arrays, scalars, and null have NO chunk leaves (the
  // anchor's buildJsonProofs leaves merkleProof === null for them).
  if (!(parsed && typeof parsed === "object" && !Array.isArray(parsed))) {
    throw new InvalidNativeJsonInput(
      "invalid_json_not_object: top level is not a JSON object and is " +
        "not a valid json-keypath-v1 disclosure source " +
        "(json-keypath-v1.md §3)"
    );
  }
  const { keys, entries } = keyEntries(parsed);
  if (keys.length === 0) {
    throw new InvalidNativeJsonInput(
      "invalid_json_empty_object: top-level object has zero keys and is " +
        "not a valid json-keypath-v1 disclosure source " +
        "(json-keypath-v1.md §3)"
    );
  }
  if (keys.length > _LEAF_ID_MAX_KEYS) {
    throw new InvalidNativeJsonInput(
      `json-keypath-v1: ${keys.length} top-level keys exceeds the ` +
        "1,000,000 cap"
    );
  }
  return { headerRow: null, keys, entries };
}

/**
 * Compute the native json-keypath-v1 STANDARD key leaves from raw file
 * bytes. NO header. Each leaf hash is the BARE sha256(utf8(per-key entry
 * string)) in sorted-key order.
 *
 * Returns the SAME {headerRow, dataRows, leafHashes} shape as
 * csv-row-v1-native / text-line-v1-native's computeNativeLeaves (with
 * headerRow === null and dataRows = the sorted-key entry strings) so
 * redact-core consumes all native profiles through one code path.
 *
 * @param {Uint8Array} fileBytes - the original JSON file as on disk.
 * @returns {Promise<{headerRow: null, dataRows: string[],
 *   leafHashes: string[]}>}
 * @throws {InvalidNativeJsonInput} on non-JSON / non-object / empty-object.
 */
export async function computeNativeLeaves(fileBytes) {
  if (!(fileBytes instanceof Uint8Array)) {
    throw new TypeError(
      `computeNativeLeaves: expected Uint8Array, got ${typeof fileBytes}`
    );
  }
  const { headerRow, keys, entries } = _canonicalKeys(fileBytes);
  const enc = new TextEncoder();
  const leafHashes = [];
  for (const entry of entries) {
    leafHashes.push(await sha256Hex(enc.encode(entry)));
  }
  // canonicalKeys[i] = the quoted canonical key literal (the exact prefix
  // each entry string is built from), in the SAME sorted order as dataRows.
  // The MASK renderer (redact-core) uses it to build "key":"[REDACTED]"
  // for a withheld key WITHOUT re-parsing the entry string.
  const canonicalKeys = keys.map((k) => JSON.stringify(k.normalize("NFC")));
  return { headerRow, dataRows: entries, leafHashes, canonicalKeys };
}

/**
 * Compute the native json-keypath-v1 SEALED key leaves from raw file
 * bytes + the 32-byte MASTER salt. NO header (shared §2/§3 canon with
 * standard). Each leaf hash is HMAC-SHA256(per-leaf salt, utf8(entry))
 * under a per-leaf salt derived by HKDF from the master salt
 * (json-keypath-v1.md §5b).
 *
 * SECURITY: this returns the per-leaf salts of EVERY key. The CALLER
 * (redact-core) base64-encodes and ships ONLY the salts of the REVEALED
 * keys, and NEVER ships the master salt. This function does no I/O and no
 * emission — it is a pure derivation. The master salt is used ONLY as the
 * HKDF IKM; it is never returned and never placed in any leaf value.
 *
 * @param {Uint8Array} fileBytes - the original JSON file as on disk.
 * @param {Uint8Array} masterSaltBytes - the 32-byte master salt (the
 *   bearer secret read from the SOURCE .mbnt manifest.json salt_b64).
 * @returns {Promise<{headerRow: null, dataRows: string[],
 *   leafHashes: string[], perLeafSalts: Uint8Array[]}>}
 * @throws {InvalidNativeJsonInput} on non-JSON / non-object / empty-object.
 * @throws {TypeError} on a non-Uint8Array / wrong-length master salt.
 */
export async function computeSealedLeaves(fileBytes, masterSaltBytes) {
  if (!(fileBytes instanceof Uint8Array)) {
    throw new TypeError(
      `computeSealedLeaves: expected Uint8Array fileBytes, got ${typeof fileBytes}`
    );
  }
  if (
    !(masterSaltBytes instanceof Uint8Array) ||
    masterSaltBytes.length !== _SEALED_MASTER_SALT_LEN
  ) {
    throw new TypeError(
      "computeSealedLeaves: masterSaltBytes must be a 32-byte Uint8Array"
    );
  }
  const { headerRow, keys, entries } = _canonicalKeys(fileBytes);
  const enc = new TextEncoder();
  const leafHashes = [];
  const perLeafSalts = [];
  for (let i = 0; i < entries.length; i++) {
    const saltI = await deriveLeafSalt(masterSaltBytes, i);
    perLeafSalts.push(saltI);
    leafHashes.push(await _hmacSha256Hex(saltI, enc.encode(entries[i])));
  }
  // Parallel to dataRows (see computeNativeLeaves): the quoted canonical
  // key literal per leaf, in sorted-key order, for the MASK renderer.
  const canonicalKeys = keys.map((k) => JSON.stringify(k.normalize("NFC")));
  return { headerRow, dataRows: entries, leafHashes, perLeafSalts, canonicalKeys };
}
