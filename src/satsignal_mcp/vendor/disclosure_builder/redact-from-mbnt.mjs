// redact-from-mbnt.mjs — the Node file-I/O wrapper around the pure
// redact-core. This is the ONLY new logic in the package: it reads the
// original file + the source .mbnt off disk, unpacks the .mbnt with the
// zero-dependency reader, calls the re-exported (UNCHANGED) pure
// buildRedactDisclosure / packDisclosureMbnt, optionally self-verifies via
// the re-exported verifyDisclosureCore, and writes the redacted copy +
// disclosure .mbnt. No new cryptography lives here.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { basename, dirname, extname, join } from "node:path";
import { createHash } from "node:crypto";

import { buildRedactDisclosure, getProfileStrategy, RedactBindingError } from "./redact-core.mjs";
import { base64UrlToBytes, packDisclosureMbnt } from "./disclosure-pack.mjs";
import { merkleRootDuplicateLast } from "./merkle.mjs";
import { readMbntMembers } from "./mbnt-read.mjs";

const _td = new TextDecoder();
function _utf8(bytes) {
  return _td.decode(bytes);
}
function _sha256hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

const _FORMAT_EXT = { csv: "csv", txt: "txt", json: "json" };

// Truncate a leaf VALUE for the --list table so a long row/span stays
// one line. Newlines/tabs in a span (text-tree spans can contain them)
// are shown as escapes so the table never breaks across lines.
const _LIST_VALUE_MAX = 60;
function _truncateValue(s) {
  const oneLine = String(s).replace(/\t/g, "\\t").replace(/\r/g, "\\r").replace(/\n/g, "\\n");
  if (oneLine.length <= _LIST_VALUE_MAX) return oneLine;
  return oneLine.slice(0, _LIST_VALUE_MAX - 1) + "…";
}

/**
 * Read the committed chunk_merkle from a parsed carrier canonical.json
 * (schema_version 1 + 2 both nest under subject.proofs.chunk_merkle), the
 * same shape redact-core reads. Returns null when absent so the caller can
 * raise a binding error in its own wording.
 * @param {Object} canonicalJson
 * @returns {?{scheme:string, algo:string, root:string}}
 */
function _readChunkMerkle(canonicalJson) {
  const cm =
    canonicalJson &&
    canonicalJson.subject &&
    canonicalJson.subject.proofs &&
    canonicalJson.subject.proofs.chunk_merkle;
  if (!cm || typeof cm !== "object" || Array.isArray(cm)) return null;
  return cm;
}

/**
 * Parse the three root members of a SOURCE .mbnt the redact path needs.
 * Shared by redactFromMbnt + the --list path so both unpack identically.
 * @param {{[name:string]: Uint8Array}} members - readMbntMembers output.
 * @param {string} [label] - bundle label for error wording (e.g. basename).
 * @returns {{canonicalJson:Object, proofsJson:Object, manifest:Object,
 *   carrierBytes:Uint8Array}}
 */
export function parseSourceMembers(members, label = "source bundle") {
  const carrierBytes = members["canonical.json"];
  if (carrierBytes == null) {
    throw new Error(`mbnt ${label} has no root canonical.json`);
  }
  if (members["proofs.json"] == null) {
    throw new Error(`mbnt ${label} has no proofs.json`);
  }
  if (members["manifest.json"] == null) {
    throw new Error(`mbnt ${label} has no manifest.json`);
  }
  return {
    canonicalJson: JSON.parse(_utf8(carrierBytes)),
    proofsJson: JSON.parse(_utf8(members["proofs.json"])),
    manifest: JSON.parse(_utf8(members["manifest.json"])),
    carrierBytes,
  };
}

/**
 * List the per-leaf reveal indices of a SOURCE anchor so an operator can
 * SEE which index maps to which row/node before picking --reveal values.
 * Recomputes the native leaves from the original file the SAME way the
 * redact path does (sealed -> computeSealedLeaves with the master salt from
 * manifest.json salt_b64; standard -> computeNativeLeaves) and HARD-FAILS
 * with a RedactBindingError if the recomputed duplicate-last root does not
 * match the carrier's committed chunk_merkle.root — i.e. the original file
 * and the bundle are not a matching pair.
 *
 * @param {Uint8Array} originalFileBytes - the ORIGINAL file (exact bytes
 *   that were anchored).
 * @param {{canonicalJson:Object, proofsJson:Object, manifest:Object}} members
 *   - the parsed source members (see parseSourceMembers); only
 *   canonicalJson + manifest are read here.
 * @returns {Promise<Array<{index:number, leaf_id:string, label:string,
 *   value:string}>>} one row per leaf, in leaf-index (sorted-path) order.
 *   For text-tree-v1 `label` is the slash path ("" shown as "(whole file)")
 *   and `value` the truncated node span; for the flat profiles `label` is
 *   the field/row label and `value` the truncated dataRows[i].
 * @throws {RedactBindingError} when the file/bundle do not match, the scheme
 *   is unsupported, or a sealed source is missing its master salt.
 */
export async function listMbntLeaves(originalFileBytes, members) {
  const { canonicalJson, manifest } = members;
  const cm = _readChunkMerkle(canonicalJson);
  if (cm == null) {
    throw new RedactBindingError(
      "carrier canonical.json has no subject.proofs.chunk_merkle — " +
        "not a per-chunk anchor bundle"
    );
  }
  const scheme = cm.scheme;
  const strategy = getProfileStrategy(scheme);
  if (!strategy) {
    throw new RedactBindingError(
      `carrier chunk_merkle.scheme is ${JSON.stringify(scheme)}; ` +
        `this tool cannot list leaves for that scheme`,
      { scheme }
    );
  }

  // Sealed source: master salt rides in the manifest as a base64url string
  // (read it the SAME way redactFromMbnt does). Standard source omits it.
  const isSealed = cm.algo === "merkle-hmac-sha256";
  let computed;
  if (isSealed) {
    if (typeof manifest.salt_b64 !== "string" || manifest.salt_b64.length === 0) {
      throw new RedactBindingError(
        "sealed source requires the 32-byte master salt from manifest.json"
      );
    }
    const masterSaltBytes = base64UrlToBytes(manifest.salt_b64);
    computed = await strategy.computeSealedLeaves(originalFileBytes, masterSaltBytes);
  } else {
    computed = await strategy.computeLeaves(originalFileBytes);
  }

  const { dataRows, leafHashes, paths, spans, pointers } = computed;

  // HARD-FAIL on file/bundle mismatch (same wording as buildRedactDisclosure).
  const committedRoot = cm.root;
  const recomputedRoot = await merkleRootDuplicateLast(leafHashes);
  if (recomputedRoot !== committedRoot) {
    throw new RedactBindingError(
      "recomputed duplicate-last merkle root does not match the bundle's " +
        "committed root. This original file and this .mbnt do not match.",
      { recomputed: recomputedRoot, committed: committedRoot }
    );
  }

  const encodeLeafId = strategy.encodeLeafId;
  const isTextTree = Array.isArray(paths) && Array.isArray(spans);
  const isJsonAst = !isTextTree && Array.isArray(pointers);
  const n = leafHashes.length;
  const rows = [];
  for (let i = 0; i < n; i++) {
    // `selector` is the copy-pastable NAME for this node — what you pass to
    // --reveal-paths / --reveal-pointers (resolveRevealNames matches on it):
    //   text-tree-v1 -> the slash path ("" = whole file)
    //   json-ast-v1  -> the RFC-6901 pointer ("" = whole document)
    //   flat profiles -> the leaf_id (the only stable name they have)
    let selector;
    let label;
    let value;
    if (isTextTree) {
      selector = paths[i];
      label = paths[i] === "" ? "(whole file)" : paths[i];
      value = _truncateValue(spans[i]);
    } else if (isJsonAst) {
      selector = pointers[i];
      label = pointers[i] === "" ? "(whole document)" : pointers[i];
      value = _truncateValue(dataRows[i]);
    } else {
      selector = encodeLeafId(i);
      label = encodeLeafId(i);
      value = _truncateValue(dataRows[i]);
    }
    rows.push({ index: i, leaf_id: encodeLeafId(i), selector, label, value });
  }
  return rows;
}

/**
 * Resolve a list of node NAMES (the `selector` column listMbntLeaves prints —
 * text-tree-v1 slash paths or json-ast-v1 RFC-6901 pointers) to 0-based reveal
 * leaf indices, so a caller can select what to reveal BY NAME instead of by
 * fragile numeric index. Recomputes the native leaves from the original file
 * (and HARD-FAILS via listMbntLeaves if the file/bundle do not match), then
 * maps each requested name to its leaf index by EXACT selector match (a
 * leaf_id is also accepted as a fallback — selectors and leaf_ids never
 * collide). Order + de-duplication of the returned indices follow the order
 * names were requested.
 *
 * @param {Uint8Array} originalFileBytes - the ORIGINAL anchored file bytes.
 * @param {{canonicalJson:Object, manifest:Object}} members - parsed source
 *   members (parseSourceMembers output), same shape listMbntLeaves takes.
 * @param {string[]} names - selectors to reveal (paths / pointers / leaf_ids).
 *   The empty string "" selects the root node (whole file / whole document) —
 *   rarely useful, since revealing the root is reveal-everything (rejected
 *   downstream as not-a-partial-disclosure). Each name is matched VERBATIM
 *   (no comma-splitting), so a selector containing a literal comma is valid
 *   here even though the CLI's comma-separated flags can't express it.
 * @returns {Promise<{indices:number[], unresolved:string[],
 *   rows:Array<{index:number, selector:string, leaf_id:string, label:string,
 *   value:string}>}>} the resolved indices, any names that matched nothing,
 *   and the full leaf rows (so a caller can show valid selectors on a miss).
 * @throws {RedactBindingError} when the file/bundle do not match (propagated
 *   from listMbntLeaves).
 */
export async function resolveRevealNames(originalFileBytes, members, names) {
  const rows = await listMbntLeaves(originalFileBytes, members);
  const bySelector = new Map();
  const byLeafId = new Map();
  for (const r of rows) {
    if (!bySelector.has(r.selector)) bySelector.set(r.selector, r.index);
    byLeafId.set(r.leaf_id, r.index);
  }
  const indices = [];
  const unresolved = [];
  const seen = new Set();
  for (const name of names) {
    let idx;
    if (bySelector.has(name)) idx = bySelector.get(name);
    else if (byLeafId.has(name)) idx = byLeafId.get(name);
    if (idx === undefined) {
      unresolved.push(name);
      continue;
    }
    if (!seen.has(idx)) {
      seen.add(idx);
      indices.push(idx);
    }
  }
  return { indices, unresolved, rows };
}

/**
 * Redact-from-original, headless: anchor source .mbnt + original file ->
 * redacted copy + disclosure .mbnt (both written to disk), self-verified.
 *
 * @param {string} originalPath - path to the ORIGINAL file (the exact
 *   bytes that were anchored).
 * @param {string} mbntPath - path to the SOURCE anchor .mbnt.
 * @param {object} [opts]
 * @param {number[]} [opts.reveal] - 0-based leaf indices to REVEAL (all others
 *   are redacted). Mutually exclusive with opts.revealNames; exactly one is
 *   required.
 * @param {string[]} [opts.revealNames] - node NAMES to REVEAL instead of
 *   numeric indices: text-tree-v1 slash paths (e.g. "/p0") or json-ast-v1
 *   RFC-6901 pointers (e.g. "/from"), as printed in the --list `selector`
 *   column. Resolved via resolveRevealNames; an unknown name hard-fails.
 * @param {"drop"|"mask"} [opts.renderMode] - render mode for MULTI-MODE
 *   profiles (json-keypath-v1, json-ast-v1, text-tree-v1): "drop" (default)
 *   or "mask". Ignored by single-mode csv/text-line profiles. Presentation
 *   only — the proof is identical either way.
 * @param {string} [opts.outDir] - output directory (mkdir -p); defaults to
 *   the original file's directory.
 * @param {boolean} [opts.selfVerify=true] - run verifyDisclosureCore on
 *   the result before returning.
 * @returns {Promise<{redactedCopyPath:string, disclosureMbntPath:string,
 *   rootHex:string, disclosureBlock:object, verify:(object|null)}>}
 */
export async function redactFromMbnt(
  originalPath,
  mbntPath,
  { reveal, revealNames, renderMode, outDir, selfVerify = true } = {}
) {
  const originalFileBytes = new Uint8Array(await readFile(originalPath));
  const mbntBytes = new Uint8Array(await readFile(mbntPath));

  const members = readMbntMembers(mbntBytes);
  const parsed = parseSourceMembers(members, basename(mbntPath));
  const { canonicalJson, proofsJson, manifest, carrierBytes } = parsed;

  // Select-by-NAME: resolve revealNames (text-tree paths / json-ast pointers)
  // to leaf indices. Mutually exclusive with numeric `reveal`.
  let selectedLeafIndices = reveal;
  if (Array.isArray(revealNames) && revealNames.length) {
    if (Array.isArray(reveal) && reveal.length) {
      throw new RedactBindingError(
        "pass either `reveal` (numeric indices) or `revealNames` " +
          "(paths/pointers), not both"
      );
    }
    const { indices, unresolved } = await resolveRevealNames(
      originalFileBytes,
      parsed,
      revealNames
    );
    if (unresolved.length) {
      throw new RedactBindingError(
        `unknown node name(s): ${unresolved.join(", ")}. Run --list to see the ` +
          `valid selectors (slash paths for text, RFC-6901 pointers for JSON).`,
        { unresolved }
      );
    }
    selectedLeafIndices = indices;
  }

  const anchorRef = {
    txid: manifest.txid ?? null,
    bundle_id:
      manifest.bundle_id ||
      manifest.proof_id ||
      basename(mbntPath).replace(/\.mbnt$/i, ""),
  };

  // Sealed source: the master salt rides in the SOURCE manifest as a
  // base64url string. Standard source omits it -> masterSaltBytes stays
  // undefined and the core takes the UNSALTED path.
  let masterSaltBytes;
  if (typeof manifest.salt_b64 === "string" && manifest.salt_b64.length) {
    masterSaltBytes = base64UrlToBytes(manifest.salt_b64);
  }

  const out = await buildRedactDisclosure({
    originalFileBytes,
    canonicalJson,
    proofsJson,
    selectedLeafIndices,
    anchorRef,
    masterSaltBytes,
    renderMode,
  });

  const zipBytes = packDisclosureMbnt({
    disclosureBlock: out.disclosureBlock,
    carrierBytes,
  });

  const dir = outDir || dirname(originalPath);
  if (outDir) await mkdir(outDir, { recursive: true });
  const base = basename(originalPath, extname(originalPath));
  const fmt = out.disclosureBlock.presentation.format;
  const ext = _FORMAT_EXT[fmt] || "txt";

  const redactedCopyPath = join(dir, `${base}.redacted.${ext}`);
  const disclosureMbntPath = join(dir, `${base}.disclosure.mbnt`);
  await writeFile(redactedCopyPath, out.redactedCopyBytes);
  await writeFile(disclosureMbntPath, zipBytes);

  let verify = null;
  if (selfVerify) {
    const onChainCommit = _sha256hex(carrierBytes);
    const { verifyDisclosureCore } = await import(
      "./verify-disclosure.mjs"
    );
    verify = await verifyDisclosureCore(out.disclosureBlock, {
      carrierBytes,
      onChainCommit,
      viewBytes: out.redactedCopyBytes,
    });
  }

  return {
    redactedCopyPath,
    disclosureMbntPath,
    rootHex: out.rootHex,
    disclosureBlock: out.disclosureBlock,
    verify,
  };
}
