// anchor-pack.mjs — turnkey HEADLESS producer of the SEALED text-tree-v1
// anchor envelope the prod notary API already accepts.
//
// WHY THIS EXISTS
// ---------------
// The envelope-assembly logic for a deep-content-hashed (text-tree-v1) `.txt`
// only existed in the BROWSER anchor form — the JS string constant
// `ANCHOR_CANON_JS` in src/satsignal_notary/customer/_anchor_canon_js.py
// (`buildAnchorProofs(file, fileBytes, mode)`, the SEALED branch). This module
// packages that EXACT assembly for node so an operator can anchor a `.txt`
// headlessly (no browser, no DOM, no JSZip/pdf.js).
//
// FAITHFUL MIRROR of buildAnchorProofs' sealed text-tree branch:
//   - byte_exact      : HMAC-SHA256(masterSalt, RAW fileBytes)  (line 486-489)
//   - content_canonical: scheme 'text-norm-v1', algo 'hmac-sha256',
//                        commitment = HMAC(masterSalt, canonBytes)  (525-528,261)
//   - chunk_merkle     : scheme 'text-tree-v1', algo 'merkle-hmac-sha256',
//                        leaf_count, root = merkleRootDuplicateLast(leafHashes)
//                        (593-602)
//   - proof_leaves     : { scheme:'text-tree-v1', merkle_leaves: leafHashes }
//   - salt_b64         : base64URL, UNPADDED  (_apBytesToBase64Url, line 123-127
//                        / 487)
//
// REUSE (no second copy of any rule): the text canon + the leaf computer + the
// merkle root are IMPORTED VERBATIM from the shipped, frozen modules — this
// module only assembles the envelope around them.
//
// Pure: no DOM, no network, no filesystem. node-testable (global crypto, Node 18+).
//
// LOCATION (persona-UX F-019, 0023 one-source): this file lives in
// web/static/disclosure-builder/ so the notary serves it at
// /static/disclosure-builder/anchor-pack.mjs (the guide-headless-anchor
// recipe fetches it without repo access). Same-directory `./` imports
// resolve in BOTH consumers: served over HTTP they hit the sibling
// /static/disclosure-builder/* entries; in-repo, node resolves the
// sibling files directly. packages/disclosure-redact/anchor-pack.mjs is
// a thin re-export shim that keeps the long-standing package import
// path stable — never fork/copy/transpile this module.

import { normalizeTextForCanonical } from "./text-line-v1-native.mjs";
import { computeSealedLeaves } from "./text-tree-v1-native.mjs";
import { computeSealedLeaves as computeSealedJsonAstLeaves } from "./json-ast-v1-native.mjs";
import { jcsCanonicalize } from "./json-keypath-v1-native.mjs";
import { merkleRootDuplicateLast } from "./merkle.mjs";

const _enc = new TextEncoder();

function _bytesToHex(bytes) {
  let out = "";
  for (const x of new Uint8Array(bytes)) out += x.toString(16).padStart(2, "0");
  return out;
}

async function _hmacHex(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, dataBytes);
  return _bytesToHex(new Uint8Array(sig));
}

// base64URL, UNPADDED — byte-for-byte _apBytesToBase64Url (_anchor_canon_js.py
// lines 123-127): standard base64 then +/->-_ and strip all trailing '='.
function _bytesToBase64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  // Node and browsers both expose global btoa; avoid Buffer for browser parity.
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Build the SEALED text-tree-v1 anchor envelope for a `.txt` file headlessly.
 *
 * Mirrors buildAnchorProofs(file, fileBytes, 'sealed') for a text file with the
 * 'tree' granularity (text-tree-v1, decision 0045 — SEALED ONLY).
 *
 * @param {Object} args
 * @param {Uint8Array} args.fileBytes - the original `.txt` file bytes as on disk.
 * @param {Uint8Array} args.masterSaltBytes - the 32-byte master salt (the bearer
 *   secret; HKDF IKM for every per-leaf salt + HMAC key for the byte/content
 *   commitments). NEVER ship this; only the per-revealed-leaf salts ride a
 *   disclosure.
 * @returns {Promise<{
 *   mode: "sealed",
 *   salt_b64: string,
 *   byte_exact_commitment: string,
 *   proof_set: {
 *     byte_exact: { algo: "hmac-sha256", commitment: string },
 *     content_canonical: { scheme: "text-norm-v1", algo: "hmac-sha256", commitment: string },
 *     chunk_merkle: { scheme: "text-tree-v1", algo: "merkle-hmac-sha256", leaf_count: number, root: string },
 *   },
 *   proof_leaves: { scheme: "text-tree-v1", merkle_leaves: string[] },
 * }>}
 * @throws {TypeError} if fileBytes is not a Uint8Array, or masterSaltBytes is
 *   not a 32-byte Uint8Array.
 */
export async function buildSealedTextTreeEnvelope({ fileBytes, masterSaltBytes } = {}) {
  if (!(fileBytes instanceof Uint8Array)) {
    throw new TypeError(
      `buildSealedTextTreeEnvelope: fileBytes must be a Uint8Array, got ${typeof fileBytes}`
    );
  }
  if (!(masterSaltBytes instanceof Uint8Array) || masterSaltBytes.length !== 32) {
    throw new TypeError(
      "buildSealedTextTreeEnvelope: masterSaltBytes must be a 32-byte Uint8Array"
    );
  }

  // byte_exact: HMAC over the RAW file bytes (buildAnchorProofs line 486).
  const byteExactCommitment = await _hmacHex(masterSaltBytes, fileBytes);

  // content_canonical: text-norm-v1 canon (blank lines KEPT — _apCanonTextTree
  // line 261 uses _apNormalizeText, NOT the non-empty-line drop). Reuse the
  // shipped canon verbatim.
  const canonText = normalizeTextForCanonical(new TextDecoder("utf-8").decode(fileBytes));
  const canonBytes = _enc.encode(canonText);
  const contentCommitment = await _hmacHex(masterSaltBytes, canonBytes);

  // chunk_merkle + proof_leaves: reuse the PROVEN leaf computer + duplicate-last
  // merkle VERBATIM (buildAnchorProofs lines 593-602). No second copy of the
  // text-tree decomposition or the merkle rule lives here.
  const { leafHashes } = await computeSealedLeaves(fileBytes, masterSaltBytes);
  const root = await merkleRootDuplicateLast(leafHashes);

  return {
    mode: "sealed",
    salt_b64: _bytesToBase64Url(masterSaltBytes),
    byte_exact_commitment: byteExactCommitment,
    proof_set: {
      byte_exact: { algo: "hmac-sha256", commitment: byteExactCommitment },
      content_canonical: {
        scheme: "text-norm-v1",
        algo: "hmac-sha256",
        commitment: contentCommitment,
      },
      chunk_merkle: {
        scheme: "text-tree-v1",
        algo: "merkle-hmac-sha256",
        leaf_count: leafHashes.length,
        root,
      },
    },
    proof_leaves: {
      scheme: "text-tree-v1",
      merkle_leaves: leafHashes,
    },
  };
}

/**
 * Build the SEALED json-ast-v1 anchor envelope for a `.json` file headlessly.
 *
 * MIRROR of buildSealedTextTreeEnvelope for the JSON deep-content (json-ast-v1,
 * granularity 'ast', decision 0042 — SEALED ONLY). Reuses the SAME _hmacHex +
 * _bytesToBase64Url helpers and the SAME duplicate-last merkle; only the canon
 * (JCS instead of text-norm-v1) and the leaf computer (json-ast-v1) differ.
 *
 *   - byte_exact      : HMAC-SHA256(masterSalt, RAW fileBytes)
 *   - content_canonical: scheme 'json-jcs-v1', algo 'hmac-sha256',
 *                        commitment = HMAC(masterSalt, utf8(jcs(JSON.parse(file))))
 *   - chunk_merkle     : scheme 'json-ast-v1', algo 'merkle-hmac-sha256',
 *                        leaf_count, root = merkleRootDuplicateLast(leafHashes)
 *   - proof_leaves     : { scheme:'json-ast-v1', merkle_leaves: leafHashes }
 *   - salt_b64         : base64URL, UNPADDED
 *
 * @param {Object} args
 * @param {Uint8Array} args.fileBytes - the original `.json` file bytes as on disk.
 * @param {Uint8Array} args.masterSaltBytes - the 32-byte master salt (bearer secret).
 * @returns {Promise<{
 *   mode: "sealed",
 *   salt_b64: string,
 *   byte_exact_commitment: string,
 *   proof_set: {
 *     byte_exact: { algo: "hmac-sha256", commitment: string },
 *     content_canonical: { scheme: "json-jcs-v1", algo: "hmac-sha256", commitment: string },
 *     chunk_merkle: { scheme: "json-ast-v1", algo: "merkle-hmac-sha256", leaf_count: number, root: string },
 *   },
 *   proof_leaves: { scheme: "json-ast-v1", merkle_leaves: string[] },
 * }>}
 * @throws {TypeError} if fileBytes is not a Uint8Array, or masterSaltBytes is
 *   not a 32-byte Uint8Array.
 */
export async function buildSealedJsonAstEnvelope({ fileBytes, masterSaltBytes } = {}) {
  if (!(fileBytes instanceof Uint8Array)) {
    throw new TypeError(
      `buildSealedJsonAstEnvelope: fileBytes must be a Uint8Array, got ${typeof fileBytes}`
    );
  }
  if (!(masterSaltBytes instanceof Uint8Array) || masterSaltBytes.length !== 32) {
    throw new TypeError(
      "buildSealedJsonAstEnvelope: masterSaltBytes must be a 32-byte Uint8Array"
    );
  }

  // byte_exact: HMAC over the RAW file bytes.
  const byteExactCommitment = await _hmacHex(masterSaltBytes, fileBytes);

  // content_canonical: JCS re-serialization of the parsed JSON (json-jcs-v1).
  // Reuse the shipped JCS canon verbatim — no second copy of the rule.
  const parsed = JSON.parse(new TextDecoder("utf-8").decode(fileBytes));
  const canonBytes = _enc.encode(jcsCanonicalize(parsed));
  const contentCommitment = await _hmacHex(masterSaltBytes, canonBytes);

  // chunk_merkle + proof_leaves: reuse the PROVEN json-ast leaf computer + the
  // duplicate-last merkle VERBATIM. No second copy of the AST decomposition or
  // the merkle rule lives here.
  const { leafHashes } = await computeSealedJsonAstLeaves(fileBytes, masterSaltBytes);
  const root = await merkleRootDuplicateLast(leafHashes);

  return {
    mode: "sealed",
    salt_b64: _bytesToBase64Url(masterSaltBytes),
    byte_exact_commitment: byteExactCommitment,
    proof_set: {
      byte_exact: { algo: "hmac-sha256", commitment: byteExactCommitment },
      content_canonical: {
        scheme: "json-jcs-v1",
        algo: "hmac-sha256",
        commitment: contentCommitment,
      },
      chunk_merkle: {
        scheme: "json-ast-v1",
        algo: "merkle-hmac-sha256",
        leaf_count: leafHashes.length,
        root,
      },
    },
    proof_leaves: {
      scheme: "json-ast-v1",
      merkle_leaves: leafHashes,
    },
  };
}

/**
 * Dispatcher: build the SEALED anchor envelope for the given granularity.
 * "tree" -> buildSealedTextTreeEnvelope (.txt / text-tree-v1);
 * "ast"  -> buildSealedJsonAstEnvelope (.json / json-ast-v1).
 *
 * @param {Object} args
 * @param {Uint8Array} args.fileBytes
 * @param {Uint8Array} args.masterSaltBytes
 * @param {"tree"|"ast"} args.granularity
 * @returns {Promise<Object>} the envelope (see the two builders above).
 * @throws {Error} on an unknown granularity.
 */
export function buildSealedEnvelope({ fileBytes, masterSaltBytes, granularity } = {}) {
  if (granularity === "tree") {
    return buildSealedTextTreeEnvelope({ fileBytes, masterSaltBytes });
  }
  if (granularity === "ast") {
    return buildSealedJsonAstEnvelope({ fileBytes, masterSaltBytes });
  }
  throw new Error(
    `buildSealedEnvelope: unknown granularity ${JSON.stringify(granularity)} ` +
      `(expected "tree" or "ast")`
  );
}
