// text-tree-v1-native.mjs — the NATIVE multi-level plain-text leaf rule
// (decision 0045). SEALED ONLY.
//
// Unlike text-line-v1 (ONE leaf per whole non-empty LINE), text-tree-v1
// commits ONE leaf per NODE of a project-owned decomposition tree — the
// whole file (path ""), every paragraph (/pN), every sentence (/pN/sM), and
// every token (/pN/sM/tK) — keyed by a slash path, in sorted-path order,
// into the SAME flat duplicate-last binary merkle. A disclosure can therefore
// prove a single token, a whole sentence, a paragraph, or the whole file from
// ONE anchor; a revealed sentence/paragraph is one compact leaf+proof.
//
// Ground truth: docs/notary_spec/profiles/text-tree-v1.md. Plain text has no
// canonical AST — this module IS the project-owned canonical decomposition
// (the tokenizer is the protocol surface, frozen byte-for-byte in §3 + the
// conformance vectors).
//
// REUSE (no §2 drift): the text canon is IMPORTED VERBATIM from
// text-line-v1-native.mjs (the exact anchor canon — strip BOM, NFC,
// CRLF/CR->LF, per-line trailing-ws strip). NOTE the deliberate divergence
// from text-line-v1: this scheme MUST NOT drop blank lines (they are the
// paragraph delimiter, §3.2), so it segments the canonical string itself, not
// text-line-v1's non-empty-line list.
//
// SEALED ONLY: text-tree-v1 has no unsalted standard mode (text-tree-v1.md
// §4/§5). computeNativeLeaves (standard sha256) is provided for the redact
// strategy interface + verifier symmetry but is UNREACHABLE in production
// (a standard text-tree-v1 carrier is rejected at anchor submit). The real
// path is computeSealedLeaves.
//
// Pure: no DOM, no jszip. node-testable.

import { normalizeTextForCanonical } from "./text-line-v1-native.mjs";
import { bytesToHex } from "./hex.mjs";

// leaf_count cap (= total node count). Matches notary/sealed.py MAX_LEAF_COUNT.
const _LEAF_COUNT_MAX = 100_000;

/**
 * Thrown when native text-tree-v1 decomposition yields no leaves or exceeds
 * the node cap.
 */
export class InvalidNativeTextTreeInput extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidNativeTextTreeInput";
  }
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

// ── SEALED-mode primitives (text-tree-v1.md §5b) ──────────────────────
// The HKDF/HMAC mechanism is the SAME the sealed CSV/text-line/keypath/json-ast
// schemes use; only the `info` PREFIX differs — text-tree-v1 uses the
// SCHEME-PREFIXED "text-tree-v1/chunk/" (distinct from the bare "chunk/" and
// from "json-ast-v1/chunk/") for forward multi-axis domain separation.
const _SEALED_HKDF_SALT = new TextEncoder().encode(
  "satsignal-sealed-v1/per-leaf"
);
const _SEALED_HKDF_INFO_PREFIX = new TextEncoder().encode("text-tree-v1/chunk/");
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
 *            info="text-tree-v1/chunk/" || u32_be(i), L=32).
 * @param {Uint8Array} masterSaltBytes - the 32-byte master salt (IKM).
 * @param {number} leafIndex - zero-based sorted-path node index.
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

// ── The frozen v1 decomposition (text-tree-v1.md §3) ──────────────────
// Deliberately boring + dependency-free: no Intl.Segmenter, no \p{...} (engine
// Unicode version drifts), no NLP. WORD_CHAR is ASCII [A-Za-z0-9] only; the
// three flanked joiners are ' (U+0027), ’ (U+2019), - (U+002D); WHITESPACE is
// exactly SPACE/TAB/LF; every other non-whitespace codepoint is its own SYMBOL
// token (incl. non-ASCII letters — a known v1 limitation, §3.4).
const _WS = new Set([" ", "\t", "\n"]);
const _JOIN = new Set(["'", "’", "-"]);
const _TERM = new Set([".", "!", "?", "…"]);

function _isWord(c) {
  return (c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || (c >= "0" && c <= "9");
}

/**
 * Tile a span by child START offsets (the first must be 0): child i =
 * [starts[i], starts[i+1]); last to end. Trailing separators ride with the
 * preceding child, so children tile the span EXACTLY (text-tree-v1.md §3.1).
 * @param {string} span
 * @param {number[]} startsIn
 * @returns {string[]} the child span strings in order
 */
function _tile(span, startsIn) {
  let starts = startsIn.filter((s) => s < span.length);
  if (!starts.length || starts[0] !== 0) starts = [0, ...starts];
  const out = [];
  for (let i = 0; i < starts.length; i++) {
    out.push(span.slice(starts[i], i + 1 < starts.length ? starts[i + 1] : span.length));
  }
  return out;
}

/** Content-block starts: 0 + the end of each blank-line run (>=2 \n). §3.2 */
function _paraStarts(s) {
  const out = [0];
  const re = /\n{2,}/g;
  let m;
  while ((m = re.exec(s)) !== null) out.push(m.index + m[0].length);
  return out;
}

/** Sentence starts: after a terminator [.!?…] followed by whitespace/end. §3.3 */
function _sentStarts(p) {
  const out = [0];
  const n = p.length;
  for (let i = 0; i < n; i++) {
    if (_TERM.has(p[i]) && (i + 1 >= n || _WS.has(p[i + 1]))) {
      let j = i + 1;
      while (j < n && _WS.has(p[j])) j++;
      if (j < n) out.push(j);
      i = j - 1;
    }
  }
  return out;
}

/** Token strings of a sentence span: WORD runs (+flanked joiners) and single
 *  SYMBOL codepoints; whitespace is a separator (not a token). §3.4 */
function _tokenize(span) {
  const toks = [];
  let i = 0;
  const n = span.length;
  while (i < n) {
    const c = span[i];
    if (_WS.has(c)) {
      i++;
      continue;
    }
    if (_isWord(c)) {
      const start = i;
      i++;
      while (i < n) {
        if (_isWord(span[i])) {
          i++;
          continue;
        }
        if (_JOIN.has(span[i]) && i + 1 < n && _isWord(span[i + 1])) {
          i += 2; // joiner flanked by WORD_CHAR -> absorb joiner + next
          continue;
        }
        break;
      }
      toks.push(span.slice(start, i));
    } else {
      toks.push(c); // single-codepoint symbol token
      i++;
    }
  }
  return toks;
}

/**
 * Decompose the canonical string into {path, value} for EVERY node — the file
 * "", every paragraph /pN, every sentence /pN/sM, every token /pN/sM/tK — in
 * DOCUMENT order. (text-tree-v1.md §3.)
 * @param {string} s - the canonical string (NFC, LF, trailing-ws-stripped, blank lines KEPT)
 * @returns {Array<{path:string, value:string}>}
 */
function decompose(s) {
  const nodes = [{ path: "", value: s }]; // the whole-file node binds every byte
  const paras = _tile(s, _paraStarts(s));
  for (let pi = 0; pi < paras.length; pi++) {
    const para = paras[pi];
    const ppath = "/p" + pi;
    nodes.push({ path: ppath, value: para });
    const sents = _tile(para, _sentStarts(para));
    for (let si = 0; si < sents.length; si++) {
      const sent = sents[si];
      const spath = ppath + "/s" + si;
      nodes.push({ path: spath, value: sent });
      const toks = _tokenize(sent);
      for (let ti = 0; ti < toks.length; ti++) {
        nodes.push({ path: spath + "/t" + ti, value: toks[ti] });
      }
    }
  }
  return nodes;
}

/**
 * The per-node leaf entry string (text-tree-v1.md §3.5):
 *   entry = JSON.stringify(path) + ":" + JSON.stringify(value)
 * THIS STRING is the leaf "value" — what sha256/HMAC hashes and what a
 * disclosure's revealed[i].value carries; the path is embedded IN it.
 * @param {string} path
 * @param {string} value
 * @returns {string}
 */
export function nodeEntry(path, value) {
  return JSON.stringify(path) + ":" + JSON.stringify(value);
}

/**
 * leaf_id = "t" + 6-digit zero-padded node index (sorted-path order).
 * Display / ordering handle only — NOT part of any hash preimage. Distinct
 * prefix from r/l/k/c/n. (text-tree-v1.md §3.5.)
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
  return "t" + String(leafIndex).padStart(6, "0");
}

/**
 * Shared canon + decomposition: decode -> canon -> decompose every node ->
 * sort by path -> entries + cap. Both modes use this; standard (§4) and sealed
 * (§5b) differ ONLY in the per-leaf hash.
 *
 * @param {Uint8Array} fileBytes
 * @returns {{paths: string[], spans: string[], entries: string[]}}
 * @throws {InvalidNativeTextTreeInput} on empty / over-cap.
 */
function _canonicalNodes(fileBytes) {
  // Lenient UTF-8 decode (U+FFFD on invalid bytes) — MATCHES the anchor.
  const text = new TextDecoder("utf-8").decode(fileBytes);
  const canonical = normalizeTextForCanonical(text);
  const nodes = decompose(canonical);
  // Deterministic order: sort by path string (UTF-16 code-unit order).
  nodes.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  if (!nodes.length) {
    throw new InvalidNativeTextTreeInput(
      "invalid_text_empty: file decomposes to zero nodes (text-tree-v1.md §3)"
    );
  }
  if (nodes.length > _LEAF_COUNT_MAX) {
    throw new InvalidNativeTextTreeInput(
      `text-tree-v1: ${nodes.length} nodes exceeds the ${_LEAF_COUNT_MAX} cap`
    );
  }
  const paths = nodes.map((n) => n.path);
  const spans = nodes.map((n) => n.value);
  const entries = nodes.map((n) => nodeEntry(n.path, n.value));
  return { paths, spans, entries };
}

/**
 * Compute the native text-tree-v1 STANDARD node leaves (bare
 * sha256(utf8(entry))). UNREACHABLE in production — text-tree-v1 is
 * sealed-only; provided for the redact-strategy interface + verifier symmetry.
 * Returns the {headerRow, dataRows, leafHashes, paths, spans} shape redact-core
 * consumes (headerRow always null — no header).
 *
 * @param {Uint8Array} fileBytes
 * @returns {Promise<{headerRow: null, dataRows: string[],
 *   leafHashes: string[], paths: string[], spans: string[]}>}
 * @throws {InvalidNativeTextTreeInput}
 */
export async function computeNativeLeaves(fileBytes) {
  if (!(fileBytes instanceof Uint8Array)) {
    throw new TypeError(
      `computeNativeLeaves: expected Uint8Array, got ${typeof fileBytes}`
    );
  }
  const { paths, spans, entries } = _canonicalNodes(fileBytes);
  const enc = new TextEncoder();
  const leafHashes = [];
  for (const entry of entries) {
    leafHashes.push(await sha256Hex(enc.encode(entry)));
  }
  return { headerRow: null, dataRows: entries, leafHashes, paths, spans };
}

/**
 * Compute the native text-tree-v1 SEALED node leaves (the ONLY mode):
 * HMAC-SHA256(per-leaf salt, utf8(entry)) under a per-leaf HKDF salt derived
 * (scheme-prefixed info) from the master salt (text-tree-v1.md §5b).
 *
 * SECURITY: returns the per-leaf salts of EVERY node. The CALLER (redact-core)
 * base64-encodes + ships ONLY the salts of the REVEALED nodes, and NEVER ships
 * the master salt. Pure derivation, no I/O.
 *
 * @param {Uint8Array} fileBytes - the original text file as on disk.
 * @param {Uint8Array} masterSaltBytes - the 32-byte master salt.
 * @returns {Promise<{headerRow: null, dataRows: string[],
 *   leafHashes: string[], perLeafSalts: Uint8Array[], paths: string[],
 *   spans: string[]}>}
 * @throws {InvalidNativeTextTreeInput} on empty / over-cap.
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
  const { paths, spans, entries } = _canonicalNodes(fileBytes);
  const enc = new TextEncoder();
  const leafHashes = [];
  const perLeafSalts = [];
  for (let i = 0; i < entries.length; i++) {
    const saltI = await deriveLeafSalt(masterSaltBytes, i);
    perLeafSalts.push(saltI);
    leafHashes.push(await _hmacSha256Hex(saltI, enc.encode(entries[i])));
  }
  return { headerRow: null, dataRows: entries, leafHashes, perLeafSalts, paths, spans };
}
