// csv-row-v1.mjs — byte-for-byte port of csv_row_v1.py.
//
// Implements docs/notary_spec/profiles/csv-row-v1.md §§2-§5:
//   - UTF-8 validity, BOM strip, CR/CRLF/LF -> LF normalization.
//   - No synthetic trailing LF.
//   - Empty input rejected.
//   - Quote-aware row splitting (RFC 4180); LF inside quoted fields
//     stays as content.
//   - leaf_id = "r" + 6-digit zero-padded decimal (max r999999).
//   - row_value_bytes = the row's canonical UTF-8 bytes WITHOUT the
//     trailing LF.
//
// Byte parity with the Python primitive is the corpus pass criterion:
// A1-A10 must produce identical canonical bytes, leaf hashes, root,
// and proof paths through this port.

import { buildPreimage, hashLeaf } from "./preimage.mjs";

export const PROFILE_LITERAL = "satsignal.csv.row.v1";

const _MAX_ROWS = 1_000_000;
const _BOM = new Uint8Array([0xef, 0xbb, 0xbf]);
const _LF = 0x0a;
const _CR = 0x0d;
const _QUOTE = 0x22;

/**
 * Thrown when csv-row-v1 canonicalization fails. The message carries
 * the spec-pinned failure code (``invalid_csv_encoding`` or
 * ``invalid_csv_empty``).
 */
export class InvalidCsvInput extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidCsvInput";
  }
}

function _startsWithBom(buf) {
  if (buf.length < 3) return false;
  return buf[0] === _BOM[0] && buf[1] === _BOM[1] && buf[2] === _BOM[2];
}

/**
 * Apply csv-row-v1 §2 canonicalization to raw input bytes.
 * @param {Uint8Array} raw
 * @returns {Uint8Array} canonical bytes
 * @throws {InvalidCsvInput} on encoding failure or empty input
 */
export function canonicalize(raw) {
  if (!(raw instanceof Uint8Array)) {
    throw new TypeError(
      `canonicalize: expected Uint8Array, got ${typeof raw}`
    );
  }
  // Decision 1: UTF-8 validity check. We don't keep the decoded string;
  // the canonicalizer operates on bytes.
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(raw);
  } catch (e) {
    throw new InvalidCsvInput(
      `invalid_csv_encoding: input is not valid UTF-8 (${e.message})`
    );
  }

  let buf = raw;

  // Decision 2: strip leading BOM if present.
  if (_startsWithBom(buf)) {
    buf = buf.subarray(3);
  }

  // Decision 3: normalize CR / CRLF / LF -> LF at the byte level.
  // Walk bytes once. CRLF -> LF; lone CR -> LF; LF -> LF.
  const normalized = [];
  let i = 0;
  const n = buf.length;
  while (i < n) {
    const b = buf[i];
    if (b === _CR) {
      normalized.push(_LF);
      if (i + 1 < n && buf[i + 1] === _LF) {
        i += 2;
      } else {
        i += 1;
      }
    } else {
      normalized.push(b);
      i += 1;
    }
  }

  // Decision 4: no synthetic trailing LF — preserve as-is.
  const out = new Uint8Array(normalized);

  // Decision §3: empty input is invalid.
  if (out.length === 0) {
    throw new InvalidCsvInput(
      "invalid_csv_empty: canonical CSV must contain at least one row"
    );
  }

  return out;
}

/**
 * RFC 4180 quote-aware row splitter. Mirrors _iter_rows() in
 * csv_row_v1.py byte-for-byte.
 * @param {Uint8Array} canonical
 * @returns {Array<Uint8Array>}
 */
function _iterRows(canonical) {
  const rows = [];
  const n = canonical.length;
  let i = 0;
  let rowStart = 0;
  let inQuotes = false;
  while (i < n) {
    const b = canonical[i];
    if (inQuotes) {
      if (b === _QUOTE) {
        // Lookahead for an escaped quote ("").
        if (i + 1 < n && canonical[i + 1] === _QUOTE) {
          i += 2;
          continue;
        }
        inQuotes = false;
        i += 1;
      } else {
        i += 1;
      }
    } else {
      if (b === _QUOTE) {
        inQuotes = true;
        i += 1;
      } else if (b === _LF) {
        rows.push(canonical.subarray(rowStart, i));
        i += 1;
        rowStart = i;
      } else {
        i += 1;
      }
    }
  }
  // Trailing partial row (no terminating LF) — decision 4 says no
  // synthetic LF, so the final partial line is a complete data row.
  if (rowStart < n) {
    rows.push(canonical.subarray(rowStart, n));
  }
  return rows;
}

/**
 * Encode a row index as the csv-row-v1 leaf_id.
 * @param {number} rowIndex - integer, 0 <= rowIndex < 1_000_000
 * @returns {string}
 * @throws {Error} if out of range
 */
export function encodeLeafId(rowIndex) {
  if (!Number.isInteger(rowIndex)) {
    throw new Error(
      `encodeLeafId: rowIndex must be integer, got ${typeof rowIndex}`
    );
  }
  if (rowIndex < 0) {
    throw new Error(`encodeLeafId: rowIndex must be >= 0, got ${rowIndex}`);
  }
  if (rowIndex >= _MAX_ROWS) {
    throw new Error(
      `encodeLeafId: rowIndex must be < ${_MAX_ROWS}, got ${rowIndex}`
    );
  }
  return "r" + String(rowIndex).padStart(6, "0");
}

/**
 * Split canonical bytes into leaves per csv-row-v1 §3.
 * @param {Uint8Array} canonical
 * @returns {Array<[string, Uint8Array]>} (leafId, rowValueBytes) tuples
 * @throws {Error} if input exceeds 1,000,000 rows
 * @throws {InvalidCsvInput} if the canonical input yields zero rows
 */
export function extractLeaves(canonical) {
  const leaves = [];
  const rows = _iterRows(canonical);
  for (let idx = 0; idx < rows.length; idx++) {
    if (idx >= _MAX_ROWS) {
      throw new Error(
        "csv-row-v1: input exceeds 1,000,000 rows; out of scope for this profile (decision 11)"
      );
    }
    // copy out the subarray so the caller can use it independently
    const row = rows[idx];
    const copy = new Uint8Array(row.length);
    copy.set(row);
    leaves.push([encodeLeafId(idx), copy]);
  }
  if (leaves.length === 0) {
    throw new InvalidCsvInput(
      "invalid_csv_empty: canonical CSV yielded zero leaves"
    );
  }
  return leaves;
}

/**
 * Compute the leaf hash for a single CSV row leaf.
 * @param {string} leafId
 * @param {Uint8Array} rowValueBytes
 * @param {Uint8Array} saltBytes - 16 raw bytes
 * @returns {Promise<string>} 64-char lowercase hex
 */
export async function leafHash(leafId, rowValueBytes, saltBytes) {
  return await hashLeaf(PROFILE_LITERAL, leafId, rowValueBytes, saltBytes);
}

/**
 * Return the raw preimage bytes (for fixture debugging).
 * @param {string} leafId
 * @param {Uint8Array} rowValueBytes
 * @param {Uint8Array} saltBytes
 * @returns {Uint8Array}
 */
export function leafPreimage(leafId, rowValueBytes, saltBytes) {
  return buildPreimage(PROFILE_LITERAL, leafId, rowValueBytes, saltBytes);
}
