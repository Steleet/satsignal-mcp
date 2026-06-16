// json-ast-v1-native.mjs — the NATIVE deep-field JSON leaf rule
// (decision 0042). SEALED ONLY.
//
// Unlike json-keypath-v1 (ONE leaf per TOP-LEVEL key), json-ast-v1 commits
// ONE leaf per JSON NODE — the document root, every object, every array,
// and every primitive — keyed by its RFC-6901 JSON Pointer, in
// sorted-pointer order, into the SAME flat duplicate-last binary merkle.
// A disclosure can therefore prove a single field, an array item, a whole
// subtree, a top-level key, or the whole file from ONE anchor; a revealed
// subtree is one compact leaf+proof.
//
// Ground truth: docs/notary_spec/profiles/json-ast-v1.md.
//
// REUSE (no §2 drift): the JCS canonicalizer is IMPORTED VERBATIM from
// json-keypath-v1-native.mjs (the exact anchor canon). Only the leaf-SET
// (one per node, not one per top-level key) and the SEALED HKDF `info`
// domain-separator differ.
//
// SEALED ONLY: json-ast-v1 has no unsalted standard mode (json-ast-v1.md
// §4/§5). computeNativeLeaves (standard sha256) is provided for the redact
// strategy interface + verifier symmetry but is UNREACHABLE in production
// (a standard json-ast-v1 carrier is rejected at anchor submit). The real
// path is computeSealedLeaves.
//
// Pure: no DOM, no jszip. node-testable.

import { jcsCanonicalize } from "./json-keypath-v1-native.mjs";
import { bytesToHex } from "./hex.mjs";

// leaf_count cap (= total node count). Matches notary/sealed.py MAX_LEAF_COUNT.
const _LEAF_COUNT_MAX = 100_000;

/**
 * Thrown when native json-ast-v1 canonicalization yields no leaves (the
 * bytes are not valid JSON) or exceeds the node cap.
 */
export class InvalidNativeJsonAstInput extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidNativeJsonAstInput";
  }
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

// ── SEALED-mode primitives (json-ast-v1.md §5b) ───────────────────────
// The HKDF/HMAC mechanism is the SAME the sealed CSV/text/keypath schemes
// use; only the `info` PREFIX differs — json-ast-v1 uses the SCHEME-PREFIXED
// "json-ast-v1/chunk/" (NOT the bare "chunk/" the three earlier schemes
// share) for forward multi-axis domain separation (decision 0042).
const _SEALED_HKDF_SALT = new TextEncoder().encode(
  "satsignal-sealed-v1/per-leaf"
);
const _SEALED_HKDF_INFO_PREFIX = new TextEncoder().encode("json-ast-v1/chunk/");
export const SEALED_ALGO = "merkle-hmac-sha256";
export const SEALED_SALT_VERSION = "salt_v1";
const _SEALED_MASTER_SALT_LEN = 32;

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
 * Per-leaf salt for sealed leaf index `i`:
 *   salt_i = HKDF-SHA256(ikm=master, salt="satsignal-sealed-v1/per-leaf",
 *            info="json-ast-v1/chunk/" || u32_be(i), L=32).
 * The `info` counter is BIG-ENDIAN u32 (DataView setUint32(..., false)).
 * The SCHEME-PREFIXED info is the json-ast-v1 forever-contract (0042); it
 * MUST match the anchor producer that mints sealed json-ast-v1 carriers.
 * @param {Uint8Array} masterSaltBytes - the 32-byte master salt (IKM).
 * @param {number} leafIndex - zero-based sorted-pointer node index.
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
 * Encode an RFC-6901 reference-token from an object key: NFC-normalize,
 * then escape "~"->"~0" and "/"->"~1" (json-ast-v1.md §3). The two
 * special characters are ASCII so NFC never changes them; the order
 * (`~` before `/`) is the RFC-6901 escaping order.
 * @param {string} key
 * @returns {string}
 */
function escapeRfc6901(key) {
  return key.normalize("NFC").replace(/~/g, "~0").replace(/\//g, "~1");
}

/**
 * Walk a parsed JSON value, pushing {pointer, value} for EVERY node — the
 * root (pointer ""), every object, every array, and every primitive —
 * into `out`. Object-key segments are escapeRfc6901(NFC(key)); array-index
 * segments are the decimal index. (json-ast-v1.md §3.)
 * @param {*} value
 * @param {string} pointer
 * @param {Array<{pointer:string, value:*}>} out
 */
function enumerateNodes(value, pointer, out) {
  out.push({ pointer, value });
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      enumerateNodes(value[i], pointer + "/" + String(i), out);
    }
  } else if (value && typeof value === "object") {
    for (const k of Object.keys(value)) {
      enumerateNodes(value[k], pointer + "/" + escapeRfc6901(k), out);
    }
  }
}

/**
 * The per-node leaf entry string (json-ast-v1.md §3), mirroring
 * json-keypath-v1's "key":jcs(value) with the POINTER in place of the key:
 *   entry = JSON.stringify(pointer) + ":" + jcsCanonicalize(value)
 * THIS STRING is the leaf "value" — what sha256/HMAC hashes and what a
 * disclosure's revealed[i].value carries; the pointer is embedded IN it.
 * @param {string} pointer
 * @param {*} value
 * @returns {string}
 */
export function nodeEntry(pointer, value) {
  return JSON.stringify(pointer) + ":" + jcsCanonicalize(value);
}

/**
 * leaf_id = "n" + 6-digit zero-padded node index (sorted-pointer order).
 * Display / ordering handle only — NOT part of any hash preimage
 * (json-ast-v1.md §3). Distinct prefix from r/l/k/c.
 * @param {number} leafIndex
 * @returns {string}
 */
export function encodeLeafId(leafIndex) {
  if (!Number.isInteger(leafIndex) || leafIndex < 0) {
    throw new Error(`encodeLeafId: bad index ${leafIndex}`);
  }
  if (leafIndex >= 1_000_000) {
    throw new Error(`encodeLeafId: index ${leafIndex} >= 1000000`);
  }
  return "n" + String(leafIndex).padStart(6, "0");
}

/**
 * Shared canon + segmentation: decode -> parse -> enumerate every node ->
 * sort by pointer -> entries + cap. Both modes use this; standard (§4) and
 * sealed (§5b) differ ONLY in the per-leaf hash.
 *
 * @param {Uint8Array} fileBytes
 * @returns {{pointers: string[], nodeValues: *[], entries: string[]}}
 * @throws {InvalidNativeJsonAstInput} on non-JSON or over-cap.
 */
function _canonicalNodes(fileBytes) {
  // Lenient UTF-8 decode (U+FFFD on invalid bytes) — MATCHES the anchor.
  const text = new TextDecoder("utf-8").decode(fileBytes);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new InvalidNativeJsonAstInput(
      "invalid_json_parse: file is not valid JSON and is not a valid " +
        "json-ast-v1 disclosure source (json-ast-v1.md §2)"
    );
  }
  // ANY top-level value is accepted (object, array, or scalar) — json-ast-v1
  // commits the whole tree (json-ast-v1.md §2), unlike json-keypath-v1's
  // objects-only gate.
  const nodes = [];
  enumerateNodes(parsed, "", nodes);
  // Deterministic order: sort by pointer string (UTF-16 code-unit order, the
  // same default sort json-keypath-v1 uses for top-level keys).
  nodes.sort((a, b) => (a.pointer < b.pointer ? -1 : a.pointer > b.pointer ? 1 : 0));
  if (nodes.length > _LEAF_COUNT_MAX) {
    throw new InvalidNativeJsonAstInput(
      `json-ast-v1: ${nodes.length} nodes exceeds the ${_LEAF_COUNT_MAX} cap`
    );
  }
  const pointers = nodes.map((n) => n.pointer);
  const nodeValues = nodes.map((n) => n.value);
  const entries = nodes.map((n) => nodeEntry(n.pointer, n.value));
  return { pointers, nodeValues, entries };
}

/**
 * Compute the native json-ast-v1 STANDARD node leaves (bare
 * sha256(utf8(entry))). UNREACHABLE in production — json-ast-v1 is
 * sealed-only; provided for the redact-strategy interface + verifier
 * symmetry. Returns the {headerRow, dataRows, leafHashes, pointers,
 * nodeValues} shape redact-core consumes (headerRow always null — no header).
 *
 * @param {Uint8Array} fileBytes
 * @returns {Promise<{headerRow: null, dataRows: string[],
 *   leafHashes: string[], pointers: string[], nodeValues: *[]}>}
 * @throws {InvalidNativeJsonAstInput}
 */
export async function computeNativeLeaves(fileBytes) {
  if (!(fileBytes instanceof Uint8Array)) {
    throw new TypeError(
      `computeNativeLeaves: expected Uint8Array, got ${typeof fileBytes}`
    );
  }
  const { pointers, nodeValues, entries } = _canonicalNodes(fileBytes);
  const enc = new TextEncoder();
  const leafHashes = [];
  for (const entry of entries) {
    leafHashes.push(await sha256Hex(enc.encode(entry)));
  }
  return { headerRow: null, dataRows: entries, leafHashes, pointers, nodeValues };
}

/**
 * Compute the native json-ast-v1 SEALED node leaves (the ONLY mode):
 * HMAC-SHA256(per-leaf salt, utf8(entry)) under a per-leaf HKDF salt
 * derived (scheme-prefixed info) from the master salt (json-ast-v1.md §5b).
 *
 * SECURITY: returns the per-leaf salts of EVERY node. The CALLER
 * (redact-core) base64-encodes + ships ONLY the salts of the REVEALED
 * nodes, and NEVER ships the master salt. Pure derivation, no I/O.
 *
 * @param {Uint8Array} fileBytes - the original JSON file as on disk.
 * @param {Uint8Array} masterSaltBytes - the 32-byte master salt.
 * @returns {Promise<{headerRow: null, dataRows: string[],
 *   leafHashes: string[], perLeafSalts: Uint8Array[], pointers: string[],
 *   nodeValues: *[]}>}
 * @throws {InvalidNativeJsonAstInput} on non-JSON / over-cap.
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
  const { pointers, nodeValues, entries } = _canonicalNodes(fileBytes);
  const enc = new TextEncoder();
  const leafHashes = [];
  const perLeafSalts = [];
  for (let i = 0; i < entries.length; i++) {
    const saltI = await deriveLeafSalt(masterSaltBytes, i);
    perLeafSalts.push(saltI);
    leafHashes.push(await _hmacSha256Hex(saltI, enc.encode(entries[i])));
  }
  return { headerRow: null, dataRows: entries, leafHashes, perLeafSalts, pointers, nodeValues };
}
