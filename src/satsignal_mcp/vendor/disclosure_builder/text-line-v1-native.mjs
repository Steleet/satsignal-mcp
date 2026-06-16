// text-line-v1-native.mjs — the NATIVE (unsalted/sealed, no-header,
// drop-empty-lines, duplicate-last) text-line-v1 leaf rule the
// redact-from-original tool binds to (0030).
//
// This is the disclosure-side port of the rule EVERY text anchor already
// commits. It is byte-for-byte the canon + leaf rule in
// src/satsignal_notary/web/templates.py:
//   - standard: `normalizeTextForCanonical` + `buildTextProofs`
//     (canonical.split('\n').filter(L => L.length>0); leaf =
//     sha256(utf8(line))), ~2107/~2116;
//   - sealed: `normalizeText`/`buildTextCanonical` (~5784/~5791) feeding
//     the GENERIC sealed merkle assembly (~6056) — per-leaf HKDF salt +
//     HMAC over the SAME non-empty canonical lines.
// Ground truth: docs/notary_spec/profiles/text-line-v1.md.
//
// Sibling of csv-row-v1-native.mjs (0029). KEY DIFFERENCES vs csv-row-v1:
//   - canon = TEXT canon (BOM strip + NFC + \r\n?→\n + per-line trailing
//     [ \t] strip), NOT CSV parse/re-quote;
//   - segmentation = split('\n').filter(L => L.length > 0) — EMPTY LINES
//     ARE DROPPED (they are not leaves); a leaf index is its position in
//     the non-empty-line list, NOT the source file line number;
//   - NO header exclusion — leaf 0 is the FIRST non-empty line (csv-row-v1
//     excludes row 0; text-line-v1 does not).
// SHARED with csv-row-v1: bare sha256(utf8(value)) standard leaf, the
// per-leaf HKDF/HMAC sealed leaf (the anchor's sealed merkle assembly is
// generic across file types), and duplicate-last-on-odd merkle.
//
// Pure: no DOM, no jszip. The browser glue (app.mjs) handles file I/O,
// unzip, and DOM; this module + the redact core are node-testable.

import { bytesToHex } from "./hex.mjs";

const _LEAF_ID_MAX_LINES = 1_000_000;

/**
 * Thrown when native text-line-v1 canonicalization yields no leaves
 * (empty / whitespace-only file). The message carries a spec-pinned
 * reason.
 */
export class InvalidNativeTextInput extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidNativeTextInput";
  }
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

// ── SEALED-mode primitives (text-line-v1.md §5b / 0030) ──────────────
// Byte-for-byte mirror of the anchor (web/templates.py deriveLeafSalt /
// hmacSha256). IDENTICAL to csv-row-v1-native.mjs's sealed primitives —
// the anchor's sealed per-leaf HKDF/HMAC derivation is generic across
// file types (the same `deriveLeafSalt`/`hmacSha256` feed every
// merkleScheme). Kept self-contained here (the csv module's copies stay
// byte-untouched) so each native profile is an independent port of its
// anchor rule.
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
 * @param {number} leafIndex - zero-based non-empty-line index.
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
 * (text-line-v1.md §5b): leaf = HMAC-SHA256(per-leaf salt, utf8(line)).
 * Byte-parity twin of `hmacSha256` (web/templates.py:5669).
 * @param {Uint8Array} keyBytes - the per-leaf salt.
 * @param {Uint8Array} msgBytes - utf8(canonical_line).
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
 * Canonicalize text exactly as the anchor does
 * (`normalizeTextForCanonical` / `normalizeText`, byte-identical in both
 * anchor branches): strip ONE leading U+FEFF (BOM), NFC, normalize line
 * endings (`\r\n` and lone `\r` → `\n`), strip trailing [ \t] per line.
 * Empty lines are preserved by THIS step (the anchor preserves them in
 * the content-canonical bytes); they are dropped later at segmentation.
 * @param {string} s
 * @returns {string}
 */
export function normalizeTextForCanonical(s) {
  if (s.length > 0 && s.charCodeAt(0) === 0xfeff) s = s.slice(1);
  s = s.normalize("NFC");
  s = s.replace(/\r\n?/g, "\n");
  s = s
    .split("\n")
    .map((L) => L.replace(/[ \t]+$/, ""))
    .join("\n");
  return s;
}

/**
 * leaf_id = "l" + 6-digit zero-padded leaf index (the position in the
 * NON-EMPTY-line list, NOT the source file line number). Display /
 * ordering handle only — NOT part of any hash preimage (text-line-v1.md
 * §3). Distinct prefix from csv-row-v1's "r" for human readability only.
 * @param {number} leafIndex
 * @returns {string}
 */
export function encodeLeafId(leafIndex) {
  if (!Number.isInteger(leafIndex) || leafIndex < 0) {
    throw new Error(`encodeLeafId: bad index ${leafIndex}`);
  }
  if (leafIndex >= _LEAF_ID_MAX_LINES) {
    throw new Error(
      `encodeLeafId: index ${leafIndex} >= ${_LEAF_ID_MAX_LINES}`
    );
  }
  return "l" + String(leafIndex).padStart(6, "0");
}

/**
 * Shared canon + segmentation: decode -> normalize -> split -> drop
 * empties -> validity caps. The SAME segmentation both modes use
 * (text-line-v1.md §2/§3): standard (§4) and sealed (§5b) differ ONLY in
 * the per-leaf hash, never in segmentation.
 *
 * @param {Uint8Array} fileBytes
 * @returns {{headerRow: null, lines: string[]}}
 *   headerRow is ALWAYS null (text-line-v1 has no header; the field is
 *   present only to keep the {headerRow, dataRows} shape the redact core
 *   shares across native profiles).
 * @throws {InvalidNativeTextInput} when there are zero non-empty lines.
 */
function _canonicalLines(fileBytes) {
  // Lenient UTF-8 decode (U+FFFD on invalid bytes) — MATCHES the anchor's
  // `file.text()`, which decodes leniently. A file the anchor accepted
  // (committing leaves over its U+FFFD-replaced lines) must recompute to
  // the SAME leaves here, not be rejected; recompute-mismatch then stays
  // the single, distinct "wrong file/bundle" failure path.
  const text = new TextDecoder("utf-8").decode(fileBytes);
  const canonical = normalizeTextForCanonical(text);
  const lines = canonical.split("\n").filter((L) => L.length > 0);
  if (lines.length === 0) {
    throw new InvalidNativeTextInput(
      "invalid_text_empty: file has zero non-empty lines and is not a " +
        "valid text-line-v1 disclosure source (text-line-v1.md §3)"
    );
  }
  if (lines.length > _LEAF_ID_MAX_LINES) {
    throw new InvalidNativeTextInput(
      `text-line-v1: ${lines.length} non-empty lines exceeds the ` +
        "1,000,000 cap"
    );
  }
  return { headerRow: null, lines };
}

/**
 * Compute the native text-line-v1 STANDARD line leaves from raw file
 * bytes. NO header. Each leaf hash is the BARE sha256(utf8(canonical
 * non-empty line)).
 *
 * Returns the SAME {headerRow, dataRows, leafHashes} shape as
 * csv-row-v1-native's computeNativeLeaves (with headerRow === null and
 * dataRows = the non-empty canonical lines) so redact-core consumes both
 * profiles through one code path.
 *
 * @param {Uint8Array} fileBytes - the original text file as on disk.
 * @returns {Promise<{headerRow: null, dataRows: string[],
 *   leafHashes: string[]}>}
 * @throws {InvalidNativeTextInput} on a zero-leaf (empty/whitespace) file.
 */
export async function computeNativeLeaves(fileBytes) {
  if (!(fileBytes instanceof Uint8Array)) {
    throw new TypeError(
      `computeNativeLeaves: expected Uint8Array, got ${typeof fileBytes}`
    );
  }
  const { headerRow, lines } = _canonicalLines(fileBytes);
  const enc = new TextEncoder();
  const leafHashes = [];
  for (const L of lines) {
    leafHashes.push(await sha256Hex(enc.encode(L)));
  }
  return { headerRow, dataRows: lines, leafHashes };
}

/**
 * Compute the native text-line-v1 SEALED line leaves from raw file bytes
 * + the 32-byte MASTER salt. NO header (shared §2/§3 canon with
 * standard). Each leaf hash is HMAC-SHA256(per-leaf salt, utf8(canonical
 * line)) under a per-leaf salt derived by HKDF from the master salt
 * (text-line-v1.md §5b).
 *
 * SECURITY: this returns the per-leaf salts of EVERY line. The CALLER
 * (redact-core) base64-encodes and ships ONLY the salts of the REVEALED
 * lines, and NEVER ships the master salt. This function does no I/O and
 * no emission — it is a pure derivation. The master salt is used ONLY as
 * the HKDF IKM; it is never returned and never placed in any leaf value.
 *
 * @param {Uint8Array} fileBytes - the original text file as on disk.
 * @param {Uint8Array} masterSaltBytes - the 32-byte master salt (the
 *   bearer secret read from the SOURCE .mbnt manifest.json salt_b64).
 * @returns {Promise<{headerRow: null, dataRows: string[],
 *   leafHashes: string[], perLeafSalts: Uint8Array[]}>}
 * @throws {InvalidNativeTextInput} on a zero-leaf file.
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
  const { headerRow, lines } = _canonicalLines(fileBytes);
  const enc = new TextEncoder();
  const leafHashes = [];
  const perLeafSalts = [];
  for (let i = 0; i < lines.length; i++) {
    const saltI = await deriveLeafSalt(masterSaltBytes, i);
    perLeafSalts.push(saltI);
    leafHashes.push(await _hmacSha256Hex(saltI, enc.encode(lines[i])));
  }
  return { headerRow, dataRows: lines, leafHashes, perLeafSalts };
}
