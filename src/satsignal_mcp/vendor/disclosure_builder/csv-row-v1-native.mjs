// csv-row-v1-native.mjs — the NATIVE (unsalted, header-excluded,
// duplicate-last) csv-row-v1 STANDARD leaf rule the redact-from-original
// tool binds to (0029).
//
// This is the disclosure-side port of the rule EVERY standard CSV anchor
// already commits. It is byte-for-byte the canon + leaf rule in
// src/satsignal_notary/customer/_anchor_canon_js.py (`_apParseCsv`,
// `_apCsvField`, `_apCanonCsv`) === web/templates.py `parseCsv` /
// `csvField` / `buildCsvProofs` standard branch. Ground truth +
// worked example: docs/notary_spec/profiles/csv-row-v1.md §§2-§6 and
// /tmp/stage5_ref/native_csv_row_v1.py.
//
// DO NOT confuse this with the retired salted csv-row-v1.mjs /
// preimage.mjs (random per-row salt, every-row-is-a-leaf,
// `profile||0x00||leaf_id||0x00||value||0x00||salt` preimage,
// promote-unchanged merkle). Those stay, inert, for the frozen salted
// corpus. This module:
//   - EXCLUDES the header row (row 0): leaves = canonicalLines.slice(1).
//   - leaf = bare sha256(utf8(canonical_data_row)) — NO salt, NO framing.
//   - merkle = DUPLICATE-LAST on odd (see merkle.mjs:buildProofPathDup /
//     merkleRootDuplicateLast).
//
// Pure: no DOM, no jszip. The browser glue (app.mjs) handles file I/O,
// unzip, and DOM; this module + the redact core are node-testable.

import { bytesToHex } from "./hex.mjs";

const _LEAF_ID_MAX_ROWS = 1_000_000;

/**
 * Thrown when native csv-row-v1 canonicalization fails (empty input /
 * header-only file). The message carries a spec-pinned reason.
 */
export class InvalidNativeCsvInput extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidNativeCsvInput";
  }
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

// ── SEALED-mode primitives (0029 §3 / csv-row-v1.md §5b) ──
// Byte-for-byte mirror of the anchor (web/templates.py deriveLeafSalt /
// hmacSha256, and customer/_anchor_canon_js.py _apDeriveLeafSalt). Used
// ONLY by computeSealedLeaves below; the standard leaf path (§4) is
// untouched. Ground truth: /tmp/stage5_ref/sealed_csv_row_v1.mjs.
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
 * Per-leaf salt for sealed data-row leaf index `i`. Byte-parity twin of
 * `deriveLeafSalt` (web/templates.py:5688) / `_apDeriveLeafSalt`:
 *   salt_i = HKDF-SHA256(ikm=master, salt="satsignal-sealed-v1/per-leaf",
 *            info="chunk/" || u32_be(i), L=32).
 * The `info` counter is BIG-ENDIAN u32 (DataView setUint32(..., false)).
 * @param {Uint8Array} masterSaltBytes - the 32-byte master salt (IKM).
 * @param {number} leafIndex - zero-based DATA-row index.
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
 * (csv-row-v1.md §5b): leaf = HMAC-SHA256(per-leaf salt, utf8(value)).
 * Byte-parity twin of `hmacSha256` (web/templates.py:5669).
 * @param {Uint8Array} keyBytes - the per-leaf salt.
 * @param {Uint8Array} msgBytes - utf8(canonical_data_row).
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
 * RFC-4180 quote-aware CSV parse. Byte-parity twin of `_apParseCsv` in
 * _anchor_canon_js.py / `parseCsv` in web/templates.py:
 *   - strips ONE leading U+FEFF (BOM);
 *   - a field opens a quoted region on `"`; inside, `""` is a literal `"`
 *     and a lone `"` closes the region; `,` outside quotes ends a field;
 *   - an unquoted LF / CR / CRLF ends a row (CRLF consumed as one break);
 *   - after the loop, a final row is appended only if the last field or
 *     row buffer is non-empty (no trailing-newline empty row).
 *
 * Operates on the decoded STRING (matching the anchor, which decodes
 * UTF-8 first), so JS string indexing mirrors the Python char loop.
 *
 * @param {string} text
 * @returns {string[][]} rows of fields
 */
export function parseCsv(text) {
  if (text.length > 0 && text.charCodeAt(0) === 0xfeff) {
    text = text.slice(1);
  }
  const rows = [];
  let row = [];
  let field = "";
  let inQuote = false;
  const n = text.length;
  for (let i = 0; i < n; i++) {
    const c = text[i];
    if (inQuote) {
      if (c === '"') {
        if (i + 1 < n && text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuote = false;
        }
      } else {
        field += c;
      }
    } else {
      if (c === '"') {
        inQuote = true;
      } else if (c === ",") {
        row.push(field);
        field = "";
      } else if (c === "\n" || c === "\r") {
        if (c === "\r" && i + 1 < n && text[i + 1] === "\n") {
          i++;
        }
        row.push(field);
        rows.push(row);
        row = [];
        field = "";
      } else {
        field += c;
      }
    }
  }
  if (field.length || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

/**
 * Minimal re-quote per field. Byte-parity twin of `_apCsvField` /
 * `csvField`: quote iff the field contains any of `"` `,` LF CR; escape
 * internal `"` to `""`.
 * @param {string} s
 * @returns {string}
 */
export function csvField(s) {
  if (/[",\n\r]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

/**
 * Canonical row = fields joined by `,` (after minimal re-quote).
 * @param {string[]} fields
 * @returns {string}
 */
export function csvRow(fields) {
  return fields.map(csvField).join(",");
}

/**
 * leaf_id = "r" + 6-digit zero-padded DATA-ROW index (NOT file-row).
 * Display / ordering handle only — NOT part of any hash preimage
 * (csv-row-v1.md §3).
 * @param {number} dataRowIndex
 * @returns {string}
 */
export function encodeLeafId(dataRowIndex) {
  if (!Number.isInteger(dataRowIndex) || dataRowIndex < 0) {
    throw new Error(`encodeLeafId: bad index ${dataRowIndex}`);
  }
  if (dataRowIndex >= _LEAF_ID_MAX_ROWS) {
    throw new Error(
      `encodeLeafId: index ${dataRowIndex} >= ${_LEAF_ID_MAX_ROWS}`
    );
  }
  return "r" + String(dataRowIndex).padStart(6, "0");
}

/**
 * Compute the native csv-row-v1 STANDARD data-row leaves from raw file
 * bytes. Header row (row 0) is EXCLUDED. Each leaf hash is the BARE
 * sha256(utf8(canonical_data_row)).
 *
 * @param {Uint8Array} fileBytes - the original CSV file as it exists on
 *   disk (raw; this function decodes UTF-8 and canonicalizes).
 * @returns {Promise<{headerRow: ?string, dataRows: string[],
 *   leafHashes: string[]}>}
 *   - headerRow: the canonical header row string (excluded from leaves),
 *     or null if the file had no rows.
 *   - dataRows: the canonical data-row strings (the leaf VALUES), in
 *     document order.
 *   - leafHashes: 64-char lowercase hex, leafHashes[i] = sha256(utf8(
 *     dataRows[i])).
 * @throws {InvalidNativeCsvInput} on empty / header-only input.
 */
export async function computeNativeLeaves(fileBytes) {
  if (!(fileBytes instanceof Uint8Array)) {
    throw new TypeError(
      `computeNativeLeaves: expected Uint8Array, got ${typeof fileBytes}`
    );
  }
  const { headerRow, dataRows } = _canonicalDataRows(fileBytes);
  const enc = new TextEncoder();
  const leafHashes = [];
  for (const r of dataRows) {
    leafHashes.push(await sha256Hex(enc.encode(r)));
  }
  return { headerRow, dataRows, leafHashes };
}

/**
 * Shared canon: decode -> parse -> header-exclude -> validity caps. The
 * SAME canon both modes use (csv-row-v1.md §2/§3): standard (§4) and
 * sealed (§5b) differ ONLY in the per-leaf hash, never in segmentation.
 * @param {Uint8Array} fileBytes
 * @returns {{headerRow: string, dataRows: string[]}}
 * @throws {InvalidNativeCsvInput}
 */
function _canonicalDataRows(fileBytes) {
  // Lenient UTF-8 decode (U+FFFD on invalid bytes) — MATCHES the anchor's
  // `file.text()` (web/templates.py), which decodes leniently. A file the
  // anchor accepted (committing leaves over its U+FFFD-replaced rows) must
  // recompute to the SAME leaves here, not be rejected; recompute-mismatch
  // then stays the single, distinct "wrong file/bundle" failure path.
  const text = new TextDecoder("utf-8").decode(fileBytes);
  const rows = parseCsv(text);
  if (rows.length === 0) {
    throw new InvalidNativeCsvInput(
      "invalid_csv_empty: file yielded zero rows"
    );
  }
  const canonicalLines = rows.map(csvRow);
  const headerRow = canonicalLines[0];
  const dataRows = canonicalLines.slice(1); // HEADER EXCLUDED
  if (dataRows.length === 0) {
    throw new InvalidNativeCsvInput(
      "invalid_csv_header_only: a header-only file has zero data leaves " +
        "and is not a valid csv-row-v1 disclosure source (csv-row-v1.md §3)"
    );
  }
  if (dataRows.length > _LEAF_ID_MAX_ROWS) {
    throw new InvalidNativeCsvInput(
      `csv-row-v1: ${dataRows.length} data rows exceeds the 1,000,000 cap`
    );
  }
  return { headerRow, dataRows };
}

/**
 * Compute the native csv-row-v1 SEALED data-row leaves from raw file
 * bytes + the 32-byte MASTER salt. Header row (row 0) is EXCLUDED (shared
 * §2/§3 canon with standard). Each leaf hash is the keyed
 * HMAC-SHA256(per-leaf salt, utf8(canonical_data_row)) under a per-leaf
 * salt derived by HKDF from the master salt (csv-row-v1.md §5b).
 *
 * SECURITY: this returns the per-leaf salts of EVERY data row. The CALLER
 * (redact-core) base64-encodes and ships ONLY the salts of the REVEALED
 * rows, and NEVER ships the master salt. This function does no I/O and no
 * emission — it is a pure derivation. The master salt is used ONLY as the
 * HKDF IKM; it is never returned and never placed in any leaf value.
 *
 * @param {Uint8Array} fileBytes - the original CSV file as on disk.
 * @param {Uint8Array} masterSaltBytes - the 32-byte master salt (the
 *   bearer secret read from the SOURCE .mbnt manifest.json salt_b64).
 * @returns {Promise<{headerRow: string, dataRows: string[],
 *   leafHashes: string[], perLeafSalts: Uint8Array[]}>}
 *   - leafHashes[i] = HMAC(perLeafSalts[i], utf8(dataRows[i])) (64-hex).
 *   - perLeafSalts[i] = the raw 32-byte HKDF per-leaf salt for row i.
 * @throws {InvalidNativeCsvInput} on empty / header-only input.
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
  const { headerRow, dataRows } = _canonicalDataRows(fileBytes);
  const enc = new TextEncoder();
  const leafHashes = [];
  const perLeafSalts = [];
  for (let i = 0; i < dataRows.length; i++) {
    const saltI = await deriveLeafSalt(masterSaltBytes, i);
    perLeafSalts.push(saltI);
    leafHashes.push(await _hmacSha256Hex(saltI, enc.encode(dataRows[i])));
  }
  return { headerRow, dataRows, leafHashes, perLeafSalts };
}
