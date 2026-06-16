// anchor-to-mbnt.mjs — the Node file-I/O + HTTP wrapper around the pure
// SEALED envelope builders (anchor-pack.mjs). This is the ONLY new
// orchestration logic the anchor side adds: it reads the original file off
// disk, generates a 32-byte master salt, dispatches to the re-used
// buildSealedEnvelope, POSTs the prod /api/v1/anchors contract, retrieves the
// server-returned SOURCE .mbnt bytes (3-way), writes them, and self-verifies
// the served bundle's committed root against a fresh recompute from the
// ORIGINAL file bytes + the master salt that rides in the .mbnt manifest.
//
// NO new cryptography: every commitment / leaf / merkle root comes from the
// re-used pure modules (decision 0023). The self-verify recompute also reuses
// the native computeSealedLeaves + merkleRootDuplicateLast VERBATIM.
//
// The master salt is the bearer secret: it is NEVER printed by this module and
// NEVER written to a standalone file. It legitimately persists ONLY inside the
// server-returned source .mbnt manifest (mirror mode).

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { basename, dirname, extname, join } from "node:path";
import { webcrypto } from "node:crypto";

import { buildSealedEnvelope } from "./anchor-pack.mjs";
import { readMbntMembers } from "./mbnt-read.mjs";
import { base64UrlToBytes } from "./disclosure-pack.mjs";
import { merkleRootDuplicateLast } from "./merkle.mjs";
import { computeSealedLeaves as computeSealedTextTreeLeaves } from "./text-tree-v1-native.mjs";
import { computeSealedLeaves as computeSealedJsonAstLeaves } from "./json-ast-v1-native.mjs";

const _td = new TextDecoder();
function _utf8(bytes) {
  return _td.decode(bytes);
}

const DEFAULT_BASE = "https://app.satsignal.cloud";

// Granularity -> { extension, scheme, native sealed-leaf computer } so the
// dispatcher + self-verify both pick the SAME profile in one place.
const _GRAN = {
  tree: { ext: "txt", scheme: "text-tree-v1", computeSealedLeaves: computeSealedTextTreeLeaves },
  ast: { ext: "json", scheme: "json-ast-v1", computeSealedLeaves: computeSealedJsonAstLeaves },
};

// File extension -> default granularity (the GOLDEN WEDGE).
const _EXT_GRAN = { ".txt": "tree", ".json": "ast" };

/**
 * Map a file path's extension to the default SEALED granularity.
 * @param {string} path
 * @returns {?("tree"|"ast")} "tree" | "ast", or null for an unknown extension.
 */
export function granularityForExt(path) {
  return _EXT_GRAN[extname(path).toLowerCase()] || null;
}

function _bytesToHex(bytes) {
  let out = "";
  for (const x of new Uint8Array(bytes)) out += x.toString(16).padStart(2, "0");
  return out;
}

/**
 * Anchor a file headlessly: build the SEALED deep-content envelope, POST the
 * prod /api/v1/anchors contract, retrieve + write the source .mbnt, and (by
 * default) self-verify the served bundle's on-chain root against a fresh
 * recompute from the ORIGINAL file bytes + the master salt in the manifest.
 *
 * @param {string} originalPath - path to the file to anchor (.txt or .json).
 * @param {object} opts
 * @param {string} [opts.apiKey] - bearer key (REQUIRED unless dryRun).
 * @param {string} [opts.base="https://app.satsignal.cloud"] - API base URL.
 * @param {string} [opts.folderSlug] - folder slug for the anchor (sent as
 *   the canonical `folder_slug` body key). Deprecated spelling
 *   `opts.matterSlug` is still accepted.
 * @param {boolean} [opts.createFolder=false] - POST /api/v1/folders first.
 *   Deprecated spelling `opts.createMatter` is still accepted.
 * @param {"tree"|"ast"} [opts.granularity] - overrides the ext-derived default.
 * @param {"mirror"|"blind"} [opts.storage="mirror"] - mirror INCLUDES salt_b64
 *   (server disk-mirrors the source .mbnt); blind OMITS it (salt never leaves).
 * @param {string} [opts.category] - optional category tag on the anchor body.
 * @param {string} [opts.filename] - override the reported filename (default
 *   basename(originalPath)).
 * @param {string} [opts.outDir] - output directory for the .mbnt (mkdir -p);
 *   defaults to the original file's directory.
 * @param {boolean} [opts.dryRun=false] - build the envelope + assemble the POST
 *   body and return WITHOUT any network call and WITHOUT writing the .mbnt.
 * @param {boolean} [opts.selfVerify=true] - recompute-verify the served .mbnt.
 * @param {Function} [opts.fetchImpl=globalThis.fetch] - injected fetch (tests).
 * @param {Function} [opts.randomBytes] - injected 32-byte salt source (tests).
 * @returns {Promise<{
 *   txid?: string, bundleId?: string, root: string, leafCount: number,
 *   scheme: string, sourceMbntPath?: string, masterSaltHex: string,
 *   verify?: (object|null), body?: object, dryRun?: boolean,
 * }>}
 */
export async function anchorToMbnt(originalPath, opts = {}) {
  const {
    apiKey,
    base = DEFAULT_BASE,
    storage = "mirror",
    category,
    filename,
    outDir,
    dryRun = false,
    selfVerify = true,
    fetchImpl = globalThis.fetch,
    randomBytes = (n) => webcrypto.getRandomValues(new Uint8Array(n)),
  } = opts;
  // Canonical option names per decision 0046; the pre-sunset spellings
  // (matterSlug/createMatter) stay accepted so existing callers don't break.
  const folderSlug = opts.folderSlug ?? opts.matterSlug;
  const createFolder = opts.createFolder ?? opts.createMatter ?? false;

  const granularity = opts.granularity || granularityForExt(originalPath);
  if (granularity !== "tree" && granularity !== "ast") {
    throw new Error(
      `anchorToMbnt: could not determine granularity for ${JSON.stringify(
        originalPath
      )} — pass granularity "tree" or "ast" (only .txt/.json auto-detect)`
    );
  }
  if (storage !== "mirror" && storage !== "blind") {
    throw new Error(
      `anchorToMbnt: storage must be "mirror" or "blind" (got ${JSON.stringify(storage)})`
    );
  }
  const prof = _GRAN[granularity];

  // Read + build. The master salt is the bearer secret — kept in-memory only.
  const fileBytes = new Uint8Array(await readFile(originalPath));
  const masterSaltBytes = randomBytes(32);
  if (!(masterSaltBytes instanceof Uint8Array) || masterSaltBytes.length !== 32) {
    throw new Error("anchorToMbnt: randomBytes(32) must return a 32-byte Uint8Array");
  }
  const masterSaltHex = _bytesToHex(masterSaltBytes);

  const envelope = await buildSealedEnvelope({ fileBytes, masterSaltBytes, granularity });
  const root = envelope.proof_set.chunk_merkle.root;
  const leafCount = envelope.proof_set.chunk_merkle.leaf_count;
  const scheme = envelope.proof_set.chunk_merkle.scheme;

  const reportedFilename = filename || basename(originalPath);

  // Assemble the POST body per the proven wire contract. mirror INCLUDES
  // salt_b64 and OMITS retain_days (never send retain_days=0 with a salt —
  // the server 400s it, decision 0044 / F-P0B-1). blind OMITS salt_b64.
  const body = {
    folder_slug: folderSlug,
    mode: "sealed",
    filename: reportedFilename,
    file_size: fileBytes.length,
    byte_exact_commitment: envelope.byte_exact_commitment,
    proof_set: envelope.proof_set,
    proof_leaves: envelope.proof_leaves,
  };
  if (storage === "mirror") {
    body.salt_b64 = envelope.salt_b64;
  }
  if (category != null) body.category = category;

  if (dryRun) {
    return { body, root, leafCount, scheme, masterSaltHex, dryRun: true };
  }

  if (!apiKey) {
    throw new Error("anchorToMbnt: apiKey is required for a live anchor");
  }
  if (typeof fetchImpl !== "function") {
    throw new Error("anchorToMbnt: no fetch implementation available");
  }

  const authHeaders = {
    Authorization: `Bearer ${apiKey}`,
    "Content-Type": "application/json",
  };

  // Optional folder create.
  if (createFolder) {
    if (!folderSlug) {
      throw new Error("anchorToMbnt: createFolder requires a folder slug");
    }
    const mres = await fetchImpl(`${base}/api/v1/folders`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({ slug: folderSlug, name: folderSlug }),
    });
    // 201 created; treat an existing folder (409) as already-present.
    if (mres.status !== 201 && mres.status !== 409 && mres.status !== 200) {
      const txt = await _safeText(mres);
      throw new Error(
        `anchorToMbnt: folder create failed (HTTP ${mres.status}): ${txt}`
      );
    }
  }

  // POST the anchor.
  const res = await fetchImpl(`${base}/api/v1/anchors`, {
    method: "POST",
    headers: authHeaders,
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const txt = await _safeText(res);
    throw new Error(`anchorToMbnt: anchor POST failed (HTTP ${res.status}): ${txt}`);
  }
  const resp = await res.json();
  const txid = resp.txid;
  // The API emits the canonical `proof_id` key (decision 0046); the
  // local `bundleId` name is this module's stable return-surface name.
  const bundleId = resp.proof_id;

  // Retrieve the source .mbnt bytes (3-way per the wire contract).
  const mbntBytes = await _retrieveSourceMbnt(resp, { base, apiKey, fetchImpl, bundleId });

  // Write <filename>.source.mbnt. Keep the FULL input filename (extension
  // included) so anchoring two same-stem files — e.g. report.txt + report.json
  // — into one directory does NOT collide on report.source.mbnt (which would
  // silently overwrite the first bundle).
  const dir = outDir || dirname(originalPath);
  if (outDir) await mkdir(outDir, { recursive: true });
  const sourceMbntPath = join(dir, `${basename(originalPath)}.source.mbnt`);
  await writeFile(sourceMbntPath, mbntBytes);

  let verify = null;
  if (selfVerify) {
    verify = await _selfVerifyServedMbnt({
      mbntBytes,
      fileBytes,
      builtRoot: root,
      computeSealedLeaves: prof.computeSealedLeaves,
    });
  }

  return {
    txid,
    bundleId,
    root,
    leafCount,
    scheme,
    sourceMbntPath,
    masterSaltHex,
    verify,
    body,
  };
}

/**
 * Retrieve the SOURCE .mbnt bytes from an anchor response, 3-way per the wire
 * contract: bundle_b64 -> bundle_url (Bearer) -> GET /bundle/{id}.mbnt (Bearer).
 * @returns {Promise<Uint8Array>}
 */
async function _retrieveSourceMbnt(resp, { base, apiKey, fetchImpl, bundleId }) {
  if (typeof resp.bundle_b64 === "string" && resp.bundle_b64.length) {
    return new Uint8Array(Buffer.from(resp.bundle_b64, "base64"));
  }
  const bearer = { Authorization: `Bearer ${apiKey}` };
  if (typeof resp.bundle_url === "string" && resp.bundle_url.length) {
    const r = await fetchImpl(resp.bundle_url, { headers: bearer });
    if (!r.ok) {
      throw new Error(
        `anchorToMbnt: bundle_url fetch failed (HTTP ${r.status})`
      );
    }
    return new Uint8Array(await r.arrayBuffer());
  }
  if (!bundleId) {
    throw new Error(
      "anchorToMbnt: response has no bundle_b64, bundle_url, or proof_id — " +
        "cannot retrieve the source .mbnt"
    );
  }
  const r = await fetchImpl(`${base}/bundle/${bundleId}.mbnt`, { headers: bearer });
  if (!r.ok) {
    throw new Error(
      `anchorToMbnt: /bundle/${bundleId}.mbnt fetch failed (HTTP ${r.status})`
    );
  }
  return new Uint8Array(await r.arrayBuffer());
}

/**
 * Self-verify the served source .mbnt — the forever-contract round-trip:
 *   1. parse the .mbnt members (readMbntMembers);
 *   2. read canonical.json.subject.proofs.chunk_merkle.root; assert == built root;
 *   3. read manifest.json.salt_b64; recompute leaves from the ORIGINAL file
 *      bytes + that salt via the native computeSealedLeaves + merkleRootDuplicateLast;
 *   4. assert recomputed root == on-chain (carrier-committed) root.
 * @returns {Promise<{ok:boolean, builtRoot:string, carrierRoot:?string,
 *   recomputedRoot:?string, fail_code:?string}>}
 */
async function _selfVerifyServedMbnt({ mbntBytes, fileBytes, builtRoot, computeSealedLeaves }) {
  const members = readMbntMembers(mbntBytes);
  if (members["canonical.json"] == null) {
    return _vfail(builtRoot, "served .mbnt has no canonical.json");
  }
  if (members["manifest.json"] == null) {
    return _vfail(builtRoot, "served .mbnt has no manifest.json");
  }
  const canonicalJson = JSON.parse(_utf8(members["canonical.json"]));
  const manifest = JSON.parse(_utf8(members["manifest.json"]));

  const cm =
    canonicalJson &&
    canonicalJson.subject &&
    canonicalJson.subject.proofs &&
    canonicalJson.subject.proofs.chunk_merkle;
  const carrierRoot = cm && typeof cm.root === "string" ? cm.root : null;
  if (carrierRoot == null) {
    return _vfail(builtRoot, "served canonical.json has no subject.proofs.chunk_merkle.root");
  }
  if (carrierRoot !== builtRoot) {
    return {
      ok: false,
      builtRoot,
      carrierRoot,
      recomputedRoot: null,
      fail_code: "carrier_root_mismatch",
    };
  }

  if (typeof manifest.salt_b64 !== "string" || manifest.salt_b64.length === 0) {
    return {
      ok: false,
      builtRoot,
      carrierRoot,
      recomputedRoot: null,
      fail_code: "manifest_missing_salt",
    };
  }
  const masterSaltBytes = base64UrlToBytes(manifest.salt_b64);
  const { leafHashes } = await computeSealedLeaves(fileBytes, masterSaltBytes);
  const recomputedRoot = await merkleRootDuplicateLast(leafHashes);
  if (recomputedRoot !== carrierRoot) {
    return {
      ok: false,
      builtRoot,
      carrierRoot,
      recomputedRoot,
      fail_code: "recompute_root_mismatch",
    };
  }
  return { ok: true, builtRoot, carrierRoot, recomputedRoot, fail_code: null };
}

function _vfail(builtRoot, msg) {
  return {
    ok: false,
    builtRoot,
    carrierRoot: null,
    recomputedRoot: null,
    fail_code: "served_mbnt_malformed",
    message: msg,
  };
}

async function _safeText(res) {
  try {
    return (await res.text()).slice(0, 500);
  } catch {
    return "<no body>";
  }
}
