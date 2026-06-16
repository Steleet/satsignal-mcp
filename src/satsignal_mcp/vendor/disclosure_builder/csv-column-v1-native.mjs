// csv-column-v1-native.mjs — the NATIVE (unsalted, header-excluded,
// duplicate-last) csv-COLUMN-v1 STANDARD leaf rule the redact-from-original
// tool binds to (decision 0040, Granularity Expansion).
//
// Column sibling of csv-row-v1-native.mjs. The orthogonal axis: ONE Merkle
// leaf per CSV *column* (by 0-based header INDEX) instead of one per data
// row. The §2 canonicalization is BYTE-IDENTICAL to csv-row-v1 §2, so
// `parseCsv` / `csvField` / `csvRow` are imported VERBATIM from the row
// module rather than re-derived (re-deriving risks BOM/quote drift; spec
// docs/notary_spec/profiles/csv-column-v1.md §2 pins "MUST match
// parseCsv / csvField exactly"). Only the segmentation + the LF column-join
// differ.
//
// The column leaf rule (csv-column-v1.md §§3-4):
//   - The HEADER row (row 0) defines the column count (ncols = leaf_count)
//     and supplies display names, but the header CELLS are EXCLUDED from
//     leaf values (only data rows 1..N contribute bytes).
//   - canonical_column_j = csvField(cell(row_i, j)) for i in 1..N, joined
//     by LF (0x0A), NO trailing newline. SHORT data rows pad missing
//     trailing positions with "" ; a LONG data row (more fields than ncols)
//     REJECTS the whole file (invalid_csv_ragged_over).
//   - leaf_hash_j = bare sha256(utf8(canonical_column_j)) — NO salt, NO
//     leaf_id, NO header name, NO 0x00 separators. UNSALTED (§4/§5).
//   - leaf_id = "c" + 3-digit zero-padded column index (display/ordering
//     only, NOT in any preimage). Cap: 1000 columns (3 digits).
//   - The merkle the anchor commits over these leaves is DUPLICATE-LAST
//     (merkle.mjs:merkleRootDuplicateLast / buildProofPathDuplicateLast),
//     NEVER the promote-unchanged disclosure/merkle.py rule — see §6.
//
// SEALED csv-column-v1 (§5b) is FROZEN by decision 0041 (Option B): its
// per-leaf HKDF `info` is the SAME bare `"chunk/" || u32_be(j)` the 3 shipped
// sealed profiles use — NOT scheme-prefixed (the multi-axis domain separation
// 0040 floated is deferred to a Phase-3 per-tree master salt). The sealed leaf
// is HMAC-SHA256(per-leaf salt, utf8(canonical_column)); `computeSealedLeaves`
// below derives the per-leaf salt via the row module's `deriveLeafSalt`
// (imported, so the bare-`"chunk/"` derivation is byte-identical to csv-row by
// construction — Option B's forever-contract invariant).
//
// Pure: no DOM, no jszip. The browser glue (app.mjs) handles file I/O,
// unzip, and DOM; this module + the redact core are node-testable.

import { bytesToHex } from "./hex.mjs";
import { parseCsv, csvField, csvRow, deriveLeafSalt } from "./csv-row-v1-native.mjs";

// 3-digit zero-padded leaf_id supports up to 1000 columns (csv-column-v1.md
// §3 cap). NOTE this DIFFERS from the row module's 1,000,000-row cap.
const _LEAF_ID_MAX_COLS = 1000;

// Sealed-mode carrier literals (csv-column-v1.md §5b, frozen by decision
// 0041 Option B). Exported for parity with the sibling native modules and so
// redact-core can reference the canonical sealed-algo string.
export const SEALED_ALGO = "merkle-hmac-sha256";
export const SEALED_SALT_VERSION = "salt_v1";

/**
 * Thrown when native csv-column-v1 canonicalization fails (empty input /
 * header-only file / over-wide row / too many columns). The message carries
 * a spec-pinned fail-code reason. The name starts with "InvalidNative" so
 * app.mjs's tryPrepare guard (`e.name.startsWith("InvalidNative")`) catches
 * it the same way it catches the row/text/json siblings.
 */
export class InvalidNativeCsvColumnInput extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidNativeCsvColumnInput";
  }
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

// ── SEALED-mode primitives (csv-column-v1.md §5b; decision 0041 Option B) ──
// The per-leaf salt derivation (`deriveLeafSalt`) is IMPORTED from
// csv-row-v1-native.mjs (top of file) so the bare-`"chunk/"` HKDF info is
// byte-identical to the 3 shipped sealed profiles BY CONSTRUCTION — Option B
// chose uniformity over a scheme-prefixed `info` (decision 0041), exactly as
// this module already imports `parseCsv`/`csvField` to avoid §2 drift. Only
// the generic HMAC leaf helper is local.
const _SEALED_MASTER_SALT_LEN = 32;

/**
 * HMAC-SHA256(key, msg) -> lowercase hex. The SEALED leaf (csv-column-v1.md
 * §5b): leaf = HMAC-SHA256(per-leaf salt, utf8(canonical_column)). Byte-parity
 * twin of the row module's `_hmacSha256Hex`.
 * @param {Uint8Array} keyBytes the per-leaf salt.
 * @param {Uint8Array} msgBytes utf8(canonical_column).
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
 * leaf_id = "c" + 3-digit zero-padded COLUMN index. Display / ordering
 * handle only — NOT part of any hash preimage (csv-column-v1.md §3).
 * @param {number} columnIndex 0-based header index.
 * @returns {string}
 */
export function encodeLeafId(columnIndex) {
  if (!Number.isInteger(columnIndex) || columnIndex < 0) {
    throw new Error(`encodeLeafId: bad index ${columnIndex}`);
  }
  if (columnIndex >= _LEAF_ID_MAX_COLS) {
    throw new Error(
      `encodeLeafId: index ${columnIndex} >= ${_LEAF_ID_MAX_COLS}`
    );
  }
  return "c" + String(columnIndex).padStart(3, "0");
}

/**
 * Shared canon: decode -> parse -> header-exclude -> column-segment ->
 * validity caps (csv-column-v1.md §§2-3). Returns the per-column canonical
 * VALUE strings (the leaf preimages) plus the raw per-column cells (for the
 * redacted-copy grid renderer) and the canonical header row string (display
 * only — NOT in any leaf).
 *
 * @param {Uint8Array} fileBytes
 * @returns {{headerRow: string, columnValues: string[], columnsCells: string[][]}}
 *   - headerRow: csvRow(header) — display only; excluded from every leaf.
 *   - columnValues[j]: the canonical column string = LF-join of the column's
 *     csvField-re-quoted data cells, no trailing newline (the leaf VALUE).
 *   - columnsCells[j]: the column's RAW data cells (post-parse, pre-csvField),
 *     in data-row order, short-row-padded with "" — for grid reconstruction.
 * @throws {InvalidNativeCsvColumnInput}
 */
function _canonicalColumns(fileBytes) {
  // Lenient UTF-8 decode (U+FFFD on invalid bytes) — MATCHES the anchor's
  // `file.text()`, which decodes leniently. A file the anchor accepted
  // (committing leaves over its U+FFFD-replaced cells) must recompute to the
  // SAME leaves here, not be rejected. Byte-identical to csv-row-v1 §2.
  const text = new TextDecoder("utf-8").decode(fileBytes);
  const rows = parseCsv(text);
  if (rows.length === 0) {
    throw new InvalidNativeCsvColumnInput(
      "invalid_csv_empty: file yielded zero rows"
    );
  }
  const header = rows[0];
  const ncols = header.length; // leaf_count == header width (§3)
  const dataFileRows = rows.slice(1); // HEADER ROW EXCLUDED
  if (dataFileRows.length === 0) {
    throw new InvalidNativeCsvColumnInput(
      "invalid_csv_header_only: a header-only file has zero data cells in " +
        "every column and is not a valid csv-column-v1 disclosure source " +
        "(csv-column-v1.md §3)"
    );
  }
  if (ncols > _LEAF_ID_MAX_COLS) {
    throw new InvalidNativeCsvColumnInput(
      `invalid_csv_too_many_columns: ${ncols} columns exceeds the ` +
        `${_LEAF_ID_MAX_COLS} cap (csv-column-v1.md §3)`
    );
  }
  // LONG-row reject: a data row wider than the header has fields with no
  // column to bind to — REJECT the whole file (§3, asymmetric with the
  // short-row pad below).
  for (const r of dataFileRows) {
    if (r.length > ncols) {
      throw new InvalidNativeCsvColumnInput(
        `invalid_csv_ragged_over: a data row has ${r.length} fields, more ` +
          `than the ${ncols}-column header (csv-column-v1.md §3)`
      );
    }
  }
  const columnsCells = [];
  const columnValues = [];
  for (let j = 0; j < ncols; j++) {
    // SHORT-row pad: a row missing trailing positions contributes "".
    const cells = dataFileRows.map((r) => (j < r.length ? r[j] : ""));
    columnsCells.push(cells);
    // csvField PER CELL, then LF-join, no trailing newline (§3). The
    // per-cell re-quote is what makes the LF join unambiguous: an in-cell
    // newline is wrapped in quotes and is byte-distinct from the separator.
    columnValues.push(cells.map(csvField).join("\n"));
  }
  return { headerRow: csvRow(header), columnValues, columnsCells };
}

/**
 * Compute the native csv-column-v1 STANDARD column leaves from raw file
 * bytes. Header row (row 0) is EXCLUDED. Each leaf hash is the BARE
 * sha256(utf8(canonical_column)).
 *
 * Returns the SAME `{headerRow, dataRows, leafHashes}` shape contract the
 * redact core consumes across all native profiles, where `dataRows` holds
 * the per-COLUMN canonical strings (the leaf VALUES) — keeping the key named
 * `dataRows` lets redact-core/app.mjs slot this strategy in with no field
 * rename. `columnsCells` is an extra field the column grid renderer uses.
 *
 * @param {Uint8Array} fileBytes the original CSV file as on disk (raw).
 * @returns {Promise<{headerRow: string, dataRows: string[],
 *   leafHashes: string[], columnsCells: string[][]}>}
 * @throws {InvalidNativeCsvColumnInput} on empty / header-only / over-wide /
 *   too-many-columns input.
 * @throws {TypeError} on a non-Uint8Array argument.
 */
export async function computeNativeLeaves(fileBytes) {
  if (!(fileBytes instanceof Uint8Array)) {
    throw new TypeError(
      `computeNativeLeaves: expected Uint8Array, got ${typeof fileBytes}`
    );
  }
  const { headerRow, columnValues, columnsCells } =
    _canonicalColumns(fileBytes);
  const enc = new TextEncoder();
  const leafHashes = [];
  for (const v of columnValues) {
    leafHashes.push(await sha256Hex(enc.encode(v)));
  }
  return { headerRow, dataRows: columnValues, leafHashes, columnsCells };
}

/**
 * Compute the native csv-column-v1 SEALED column leaves from raw file bytes +
 * the 32-byte MASTER salt. Header row (row 0) is EXCLUDED (shared §2/§3 canon
 * with standard — only the per-leaf hash differs, never the segmentation).
 * Each leaf hash is HMAC-SHA256(per-leaf salt, utf8(canonical_column)) under a
 * per-leaf salt derived by HKDF from the master salt (csv-column-v1.md §5b;
 * decision 0041 Option B — the bare `"chunk/" || u32_be(j)` info, derived via
 * the imported `deriveLeafSalt` so it is byte-identical to csv-row-v1).
 *
 * SECURITY: returns the per-leaf salts of EVERY column. The CALLER
 * (redact-core) base64-encodes and ships ONLY the salts of the REVEALED
 * columns, and NEVER ships the master salt (the master-salt-strip rule,
 * csv-row-v1.md §5b.1). This function does no I/O and no emission; the master
 * salt is used ONLY as the HKDF IKM and never returned or placed in any leaf.
 *
 * Returns the SAME `{headerRow, dataRows, leafHashes, columnsCells}` shape the
 * redact core consumes across all native profiles (where `dataRows` holds the
 * per-COLUMN canonical strings), plus `perLeafSalts` — mirroring the row
 * module's sealed return.
 *
 * @param {Uint8Array} fileBytes the original CSV file as on disk (raw).
 * @param {Uint8Array} masterSaltBytes the 32-byte master salt (HKDF IKM; read
 *   from the SOURCE .mbnt manifest.json salt_b64).
 * @returns {Promise<{headerRow: string, dataRows: string[],
 *   leafHashes: string[], columnsCells: string[][], perLeafSalts: Uint8Array[]}>}
 *   - leafHashes[j] = HMAC(perLeafSalts[j], utf8(columnValues[j])) (64-hex).
 *   - perLeafSalts[j] = the raw 32-byte HKDF per-leaf salt for column j.
 * @throws {InvalidNativeCsvColumnInput} on empty / header-only / over-wide /
 *   too-many-columns input.
 * @throws {TypeError} on a non-Uint8Array / wrong-length argument.
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
  const { headerRow, columnValues, columnsCells } =
    _canonicalColumns(fileBytes);
  const enc = new TextEncoder();
  const leafHashes = [];
  const perLeafSalts = [];
  for (let j = 0; j < columnValues.length; j++) {
    const saltJ = await deriveLeafSalt(masterSaltBytes, j);
    perLeafSalts.push(saltJ);
    leafHashes.push(await _hmacSha256Hex(saltJ, enc.encode(columnValues[j])));
  }
  return {
    headerRow,
    dataRows: columnValues,
    leafHashes,
    columnsCells,
    perLeafSalts,
  };
}
