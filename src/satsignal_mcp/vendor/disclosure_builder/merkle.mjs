// merkle.mjs — byte-for-byte port of merkle.py.
//
// Pins the four merkle proof invariants from
// docs/notary_spec/disclosure-v1.md §3.4:
//   1. Hash algorithm: SHA-256, lowercase hex on the wire, 64 chars.
//   2. Single-leaf tree: root == leaf_hash, proof_path == [].
//   3. Odd-node behavior: promote unchanged (NEVER duplicate-and-rehash).
//   4. Raw-byte concatenation: sibling_bytes || frontier_bytes (or vice
//      versa per side); SHA-256 over the 64-byte buffer.
//   5. Hash format: ^[0-9a-f]{64}$ — uppercase or mis-length is a
//      programmer-error exception.

import { bytesToHex, hexToBytes, isHex64 } from "./hex.mjs";

async function sha256Concat(left, right) {
  const buf = new Uint8Array(64);
  buf.set(left, 0);
  buf.set(right, 32);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return new Uint8Array(digest);
}

function _check64(hex, name) {
  if (!isHex64(hex)) {
    throw new Error(
      `${name}: not 64 lowercase hex characters (^[0-9a-f]{64}$)`
    );
  }
  return hexToBytes(hex);
}

/**
 * Build the merkle root over a list of 64-char-hex leaf hashes.
 *
 * @param {string[]} leafHashesHex - each 64-char lowercase hex
 * @returns {Promise<string>} root as 64-char lowercase hex
 */
export async function merkleRoot(leafHashesHex) {
  if (!Array.isArray(leafHashesHex) || leafHashesHex.length === 0) {
    throw new Error("merkleRoot: leaf-set MUST be non-empty");
  }
  let level = leafHashesHex.map((h, i) => _check64(h, `leafHashes[${i}]`));
  while (level.length > 1) {
    const next = [];
    let i = 0;
    for (; i + 1 < level.length; i += 2) {
      next.push(await sha256Concat(level[i], level[i + 1]));
    }
    if (i < level.length) {
      next.push(level[i]); // promote unchanged
    }
    level = next;
  }
  return bytesToHex(level[0]);
}

/**
 * Walk a merkle proof from a leaf hash to a candidate root.
 *
 * @param {string} leafHashHex
 * @param {Array<{side: "L"|"R", hash: string}>} proofPath
 * @param {string} rootHex
 * @returns {Promise<boolean>}
 */
export async function verifyProofPath(leafHashHex, proofPath, rootHex) {
  let frontier = _check64(leafHashHex, "leafHash");
  const rootBytes = _check64(rootHex, "root");
  for (let i = 0; i < proofPath.length; i++) {
    const entry = proofPath[i];
    if (!entry || (entry.side !== "L" && entry.side !== "R")) {
      throw new Error(
        `proofPath[${i}].side: must be 'L' or 'R', got ${JSON.stringify(entry?.side)}`
      );
    }
    const sibling = _check64(entry.hash, `proofPath[${i}].hash`);
    if (entry.side === "L") {
      frontier = await sha256Concat(sibling, frontier);
    } else {
      frontier = await sha256Concat(frontier, sibling);
    }
  }
  return bytesToHex(frontier) === bytesToHex(rootBytes);
}

/**
 * Compute the merkle proof path for a single leaf, given level-0
 * leaf hashes. Mirrors the proof_path[] shape inside
 * disclosure_block.revealed[].proof_path.
 *
 * @param {string[]} leafHashesHex
 * @param {number} leafIndex
 * @returns {Promise<Array<{side: "L"|"R", hash: string}>>}
 */
export async function buildProofPath(leafHashesHex, leafIndex) {
  if (!Array.isArray(leafHashesHex) || leafHashesHex.length === 0) {
    throw new Error("buildProofPath: leaf-set MUST be non-empty");
  }
  if (leafIndex < 0 || leafIndex >= leafHashesHex.length) {
    throw new Error(
      `buildProofPath: leafIndex ${leafIndex} out of range`
    );
  }
  let level = leafHashesHex.map((h, i) => _check64(h, `leafHashes[${i}]`));
  let idx = leafIndex;
  const path = [];
  while (level.length > 1) {
    const lastIdxIsOddPromote =
      level.length % 2 === 1 && idx === level.length - 1;
    if (!lastIdxIsOddPromote) {
      const isLeft = idx % 2 === 0;
      const siblingIdx = isLeft ? idx + 1 : idx - 1;
      path.push({
        side: isLeft ? "R" : "L",
        hash: bytesToHex(level[siblingIdx]),
      });
    }
    const next = [];
    let i = 0;
    for (; i + 1 < level.length; i += 2) {
      next.push(await sha256Concat(level[i], level[i + 1]));
    }
    if (i < level.length) {
      next.push(level[i]);
    }
    idx = Math.floor(idx / 2);
    level = next;
  }
  return path;
}

// ---------------------------------------------------------------------
// DUPLICATE-LAST variants (0029) — for the NATIVE csv-row-v1
// merkle the anchor commits. The promote-unchanged variants above stay
// for the inert salted corpus; do NOT delete them.
//
// Difference from promote-unchanged: an odd-count level's unpaired LAST
// node self-pairs — `right = level[i]` — and the parent is
// SHA-256(raw(level[i]) || raw(level[i])). So the proof path for that
// odd node carries a SELF-SIBLING { side:"R", hash: level[idx] } (its
// own hash). The verifier walk (verifyProofPath) is structure-agnostic
// and verifies both shapes UNCHANGED — only the builder differs. Mirrors
// /tmp/stage5_ref/native_csv_row_v1.py::build_proof_path_duplicate_last
// + merkle_root_duplicate_last and merkleRootFromHexLeaves in
// web/templates.py.
// ---------------------------------------------------------------------

/**
 * Build the DUPLICATE-LAST merkle root over 64-hex leaf hashes.
 * Useful for tests (the redact core walks proof paths instead of
 * rebuilding the root, but a root builder lets tests construct + assert
 * carriers without the Python reference impl).
 *
 * @param {string[]} leafHashesHex
 * @returns {Promise<string>} root as 64-char lowercase hex
 */
export async function merkleRootDuplicateLast(leafHashesHex) {
  if (!Array.isArray(leafHashesHex) || leafHashesHex.length === 0) {
    throw new Error("merkleRootDuplicateLast: leaf-set MUST be non-empty");
  }
  let level = leafHashesHex.map((h, i) => _check64(h, `leafHashes[${i}]`));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(await sha256Concat(left, right));
    }
    level = next;
  }
  return bytesToHex(level[0]);
}

/**
 * Compute the DUPLICATE-LAST merkle proof path for a single leaf.
 * For the odd-promoted last node at any level, emits a SELF-SIBLING
 * { side:"R", hash: level[idx] } (the node's own hash) and reduces the
 * level via SHA-256(left||left). Non-last (or even-positioned) nodes
 * keep the standard even/odd sibling logic.
 *
 * @param {string[]} leafHashesHex
 * @param {number} leafIndex
 * @returns {Promise<Array<{side: "L"|"R", hash: string}>>}
 */
export async function buildProofPathDuplicateLast(leafHashesHex, leafIndex) {
  if (!Array.isArray(leafHashesHex) || leafHashesHex.length === 0) {
    throw new Error("buildProofPathDuplicateLast: leaf-set MUST be non-empty");
  }
  if (leafIndex < 0 || leafIndex >= leafHashesHex.length) {
    throw new Error(
      `buildProofPathDuplicateLast: leafIndex ${leafIndex} out of range`
    );
  }
  let level = leafHashesHex.map((h, i) => _check64(h, `leafHashes[${i}]`));
  let idx = leafIndex;
  const path = [];
  while (level.length > 1) {
    const isLastOdd = level.length % 2 === 1 && idx === level.length - 1;
    if (isLastOdd) {
      // Self-sibling: the odd-promoted node pairs with ITSELF.
      path.push({ side: "R", hash: bytesToHex(level[idx]) });
    } else {
      const isLeft = idx % 2 === 0;
      const siblingIdx = isLeft ? idx + 1 : idx - 1;
      path.push({
        side: isLeft ? "R" : "L",
        hash: bytesToHex(level[siblingIdx]),
      });
    }
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(await sha256Concat(left, right));
    }
    idx = Math.floor(idx / 2);
    level = next;
  }
  return path;
}
