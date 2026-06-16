// verify-disclosure.mjs — pure verification core for
// satsignal.disclosure.v1, byte-parity twin of
// src/satsignal_notary/disclosure/verifier.py:verify_disclosure.
//
// No DOM, no jszip. Imports only the shared disclosure
// primitives so the Builder + the /verify page + tests/verifier all run
// ONE JS implementation (decision 0023; locked in 0027 §1). The caller
// (verifier.html) handles zip extraction, the chain lookup for the
// on-chain commitment, and DOM rendering; tests import this module
// headlessly and feed corpus inputs directly.
//
// Replicates verifier.py's fail-fast order and the exact fail-code
// strings. See disclosure-v1.md §4 (binding chain) + §7 (per-leaf) and
// CONFORMANCE_disclosure.md §A–§E for the code catalogue.

import { leafHash, PROFILE_LITERAL } from "./csv-row-v1.mjs";
import { verifyProofPath } from "./merkle.mjs";
import { base64ToBytes } from "./base64.mjs";
import { bytesToHex } from "./hex.mjs";

const _DISCLOSURE_VERSION_LITERAL = "satsignal.disclosure.v1";

// The native (unsalted) literals anchors actually emit (0029
// csv-row-v1; 0030 text-line-v1; 0031
// json-keypath-v1). Distinct from the salted dotted `satsignal.csv.row.v1`
// (PROFILE_LITERAL above). The native leaf recompute is profile-AGNOSTIC —
// bare sha256(utf8(value)) standard / HMAC(per-leaf salt, utf8(value))
// sealed — so a new native profile joins the set with no new leaf code
// (the value-bytes rule = utf8(value) for csv-row-v1 (canonical row),
// text-line-v1 (canonical line), and json-keypath-v1 (the per-key entry
// string)). Inlined below over the shared sha256Hex/hmacSha256Hex, so no
// new served .mjs / three-touch is needed for the verifier.
const _CSV_ROW_V1_NATIVE_PROFILE = "csv-row-v1";
const _TEXT_LINE_V1_NATIVE_PROFILE = "text-line-v1";
const _JSON_KEYPATH_V1_NATIVE_PROFILE = "json-keypath-v1";
const _CSV_COLUMN_V1_NATIVE_PROFILE = "csv-column-v1";
const _JSON_AST_V1_NATIVE_PROFILE = "json-ast-v1";
const _TEXT_TREE_V1_NATIVE_PROFILE = "text-tree-v1";
// Profiles that bind to the anchor's NATIVE chunk_merkle (bare-sha256
// standard / per-leaf-HMAC sealed). The native recompute is profile-agnostic
// (utf8(value)). json-ast-v1 (0042) + text-tree-v1 (0045) are native +
// SEALED-ONLY.
const _NATIVE_PROFILES = new Set([
  _CSV_ROW_V1_NATIVE_PROFILE,
  _TEXT_LINE_V1_NATIVE_PROFILE,
  _JSON_KEYPATH_V1_NATIVE_PROFILE,
  _CSV_COLUMN_V1_NATIVE_PROFILE,
  _JSON_AST_V1_NATIVE_PROFILE,
  _TEXT_TREE_V1_NATIVE_PROFILE,
]);
// Native profiles for which salt_b64 is OPTIONAL on revealed entries (they
// have an unsalted STANDARD mode): absent for standard, present for sealed.
// json-ast-v1 is SEALED-ONLY, so it is NOT here — salt_b64 is REQUIRED for it
// and a missing salt fails closed structurally (invalid_disclosure_structure).
// Mirrors manifest_schema.py `_NATIVE_PROFILE_LITERALS` (the salt-optional set,
// which also excludes json-ast-v1) — distinct from _NATIVE_PROFILES.
const _SALT_OPTIONAL_PROFILES = new Set([
  _CSV_ROW_V1_NATIVE_PROFILE,
  _TEXT_LINE_V1_NATIVE_PROFILE,
  _JSON_KEYPATH_V1_NATIVE_PROFILE,
  _CSV_COLUMN_V1_NATIVE_PROFILE,
]);
// Native profiles whose SEALED mode (algo "merkle-hmac-sha256") is FROZEN
// and accepted at §4 step 5 — a SUBSET of _NATIVE_PROFILES. csv-column-v1's
// sealed §5b is frozen by decision 0041 (Option B: the bare "chunk/" info,
// same as the other 3 — NOT scheme-prefixed). json-ast-v1 (0042) is sealed-only
// and FROZEN with a SCHEME-PREFIXED "json-ast-v1/chunk/" info, so it IS here
// too. All accept the sealed algo on equal terms. Mirrors verifier.py
// `_NATIVE_SEALED_LITERALS`.
const _NATIVE_SEALED_PROFILES = new Set([
  _CSV_ROW_V1_NATIVE_PROFILE,
  _TEXT_LINE_V1_NATIVE_PROFILE,
  _JSON_KEYPATH_V1_NATIVE_PROFILE,
  _CSV_COLUMN_V1_NATIVE_PROFILE,
  _JSON_AST_V1_NATIVE_PROFILE,
  // text-tree-v1 (0045) is sealed-only + FROZEN with a SCHEME-PREFIXED
  // "text-tree-v1/chunk/" info, so it IS here (like json-ast-v1).
  _TEXT_TREE_V1_NATIVE_PROFILE,
]);

// The sealed-mode carrier algo + salt_version literals (csv-row-v1.md §5b /
// 0029 §3). Standard native carriers pin `algo: "sha256"` (unsalted
// bare sha256); sealed native carriers pin `algo: "merkle-hmac-sha256"`
// with `salt_version: "salt_v1"` (HMAC leaf under the published per-leaf
// salt). The sealed algo is accepted for ANY native profile
// {csv-row-v1, text-line-v1, json-keypath-v1} (0030/0031 repeat the
// csv-row-v1 §5b pattern); `sha256` is accepted for every implemented
// profile.
const _NATIVE_SEALED_ALGO = "merkle-hmac-sha256";
const _CSV_ROW_V1_SEALED_SALT_VERSION = "salt_v1";

// Implemented profiles: the salted dotted CSV profile (inert legacy
// corpus) AND the native csv-row-v1 / text-line-v1 /
// json-keypath-v1. json.field.v1 and text.paragraph_sentence.v1
// still have no JS impl, so they fail closed at §7 step 3 with
// `unsupported_profile` (0027 §3).
// Exported so tests/verifier/test_supported_profiles_parity.mjs can pin
// that the profiles failcodes.mjs advertises in `unsupported_profile`
// match the set verifyDisclosureCore actually dispatches (WG4 / P-RA-1).
export const _IMPLEMENTED_PROFILES = new Set([
  PROFILE_LITERAL,
  _CSV_ROW_V1_NATIVE_PROFILE,
  _TEXT_LINE_V1_NATIVE_PROFILE,
  _JSON_KEYPATH_V1_NATIVE_PROFILE,
  _CSV_COLUMN_V1_NATIVE_PROFILE,
  _JSON_AST_V1_NATIVE_PROFILE,
  _TEXT_TREE_V1_NATIVE_PROFILE,
]);

const HEX64_RE = /^[0-9a-f]{64}$/;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

// Minimum width for a valid on-chain document commitment. The live
// on-chain value is the 20-byte (40-hex) PREFIX of the document hash;
// the corpus supplies the full 64-hex hash. 40 lowercase-hex chars is
// the safe floor — anything shorter (incl. an empty string) cannot
// validly bind the carrier to the chain, and would let an empty commit
// satisfy the §4 step 2 prefix compare VACUOUSLY (slice(0,0) === "").
const _MIN_ONCHAIN_COMMIT_HEX_LEN = 40;
const _ONCHAIN_COMMIT_HEX_RE = /^[0-9a-f]+$/;

const _REQUIRED_DOES_NOT_PROVE_CODES = [
  "incomplete_by_design",
  "redacted_view_not_original",
  "satsignal_does_not_certify",
];
const _REQUIRED_PROVES_CODES_BASE = ["leaf_set_membership", "leaf_value_match"];

function fail(code) {
  return { ok: false, fail_code: code };
}
function ok() {
  return { ok: true, fail_code: null };
}

function isStr(v) {
  return typeof v === "string";
}
function isNonEmptyStr(v) {
  return typeof v === "string" && v.length > 0;
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

// HMAC-SHA256(key, msg) -> lowercase hex. The SEALED csv-row-v1 leaf
// (csv-row-v1.md §5b): leaf = HMAC-SHA256(per-leaf salt, utf8(value)).
// Mirrors csv_row_v1_native.sealed_leaf_hash (hmac+hashlib) byte-for-byte.
async function hmacSha256Hex(keyBytes, msgBytes) {
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

// ---------------------------------------------------------------------
// Structural validation. Mirrors manifest_schema.validate_disclosure_block
// closely enough to surface the SAME fail codes the Python verifier's
// _classify_schema_error produces:
//   "64 lowercase hex characters" prose -> invalid_hash_format
//   "missing required code" prose       -> missing_claim_code
//   "must equal linked_anchor..."       -> profile_mismatch
//   anything else                       -> invalid_disclosure_structure
// We return the classified CODE directly (first error wins, fail-fast).
// ---------------------------------------------------------------------

function _validateClaimArray(arr, requiredCodes) {
  // returns a fail code string or null
  if (!Array.isArray(arr)) return "invalid_disclosure_structure";
  const seen = new Set();
  for (const entry of arr) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      return "invalid_disclosure_structure";
    }
    if (!("code" in entry)) return "invalid_disclosure_structure";
    if (!isNonEmptyStr(entry.code)) return "invalid_disclosure_structure";
    seen.add(entry.code);
    if (!("text" in entry)) return "invalid_disclosure_structure";
    if (!isNonEmptyStr(entry.text)) return "invalid_disclosure_structure";
  }
  for (const code of requiredCodes) {
    if (!seen.has(code)) return "missing_claim_code";
  }
  return null;
}

function _structuralFailCode(block) {
  // Returns a fail code string, or null when structurally sound.
  // Mirrors the field order of validate_disclosure_block; the FIRST
  // violation determines the code (fail-fast parity with Python, which
  // classifies structural_errors[0]).
  if (block === null || typeof block !== "object" || Array.isArray(block)) {
    return "invalid_disclosure_structure";
  }

  // disclosure_id
  if (!("disclosure_id" in block)) return "invalid_disclosure_structure";
  if (!isNonEmptyStr(block.disclosure_id)) return "invalid_disclosure_structure";

  // linked_anchor
  if (!("linked_anchor" in block)) return "invalid_disclosure_structure";
  const la = block.linked_anchor;
  if (la === null || typeof la !== "object" || Array.isArray(la)) {
    return "invalid_disclosure_structure";
  }
  for (const key of ["root", "txid", "subject_profile", "bundle_id"]) {
    if (!(key in la)) return "invalid_disclosure_structure";
  }
  if (!isStr(la.root) || !HEX64_RE.test(la.root)) return "invalid_hash_format";
  if (!isStr(la.txid) || !HEX64_RE.test(la.txid)) return "invalid_hash_format";
  if (!isNonEmptyStr(la.subject_profile)) return "invalid_disclosure_structure";
  if (!isNonEmptyStr(la.bundle_id)) return "invalid_disclosure_structure";
  const subjectProfile = la.subject_profile;

  // revealed
  if (!("revealed" in block)) return "invalid_disclosure_structure";
  const revealed = block.revealed;
  if (!Array.isArray(revealed) || revealed.length === 0) {
    return "invalid_disclosure_structure";
  }
  for (const entry of revealed) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      return "invalid_disclosure_structure";
    }
    if (!("leaf_id" in entry) || !isNonEmptyStr(entry.leaf_id)) {
      return "invalid_disclosure_structure";
    }
    if (!("profile" in entry)) return "invalid_disclosure_structure";
    if (!isNonEmptyStr(entry.profile)) return "invalid_disclosure_structure";
    if (entry.profile !== subjectProfile) return "profile_mismatch";
    if (!("value" in entry)) return "invalid_disclosure_structure";
    // salt_b64 is PROFILE-GATED (0029 §5): OPTIONAL for native
    // csv-row-v1 (unsalted standard), REQUIRED for the salted dotted
    // profiles. If present it must still be valid base64 either way.
    const saltOptional = _SALT_OPTIONAL_PROFILES.has(subjectProfile);
    if (!("salt_b64" in entry)) {
      if (!saltOptional) return "invalid_disclosure_structure";
    } else if (
      !isNonEmptyStr(entry.salt_b64) ||
      !BASE64_RE.test(entry.salt_b64)
    ) {
      return "invalid_disclosure_structure";
    }
    if (!("leaf_hash" in entry)) return "invalid_disclosure_structure";
    if (!isStr(entry.leaf_hash) || !HEX64_RE.test(entry.leaf_hash)) {
      return "invalid_hash_format";
    }
    if (!("proof_path" in entry)) return "invalid_disclosure_structure";
    if (!Array.isArray(entry.proof_path)) return "invalid_disclosure_structure";
    for (const pp of entry.proof_path) {
      if (pp === null || typeof pp !== "object" || Array.isArray(pp)) {
        return "invalid_disclosure_structure";
      }
      if (pp.side !== "L" && pp.side !== "R") {
        return "invalid_disclosure_structure";
      }
      if (!isStr(pp.hash) || !HEX64_RE.test(pp.hash)) {
        return "invalid_hash_format";
      }
    }
  }

  // presentation (optional) — only the view_sha256 hex format matters
  // for the fail-code surface this core needs; deeper presentation
  // shape checks are not gating.
  const hasPresentation = "presentation" in block;
  if (hasPresentation) {
    const p = block.presentation;
    if (p === null || typeof p !== "object" || Array.isArray(p)) {
      return "invalid_disclosure_structure";
    }
    if ("view_sha256" in p) {
      if (!isStr(p.view_sha256) || !HEX64_RE.test(p.view_sha256)) {
        return "invalid_hash_format";
      }
    }
  }

  // claims
  if (!("claims" in block)) return "invalid_disclosure_structure";
  const claims = block.claims;
  if (claims === null || typeof claims !== "object" || Array.isArray(claims)) {
    return "invalid_disclosure_structure";
  }
  if (!("proves" in claims)) return "invalid_disclosure_structure";
  const provesRequired = _REQUIRED_PROVES_CODES_BASE.slice();
  if (hasPresentation) provesRequired.push("presentation_integrity");
  const provesCode = _validateClaimArray(claims.proves, provesRequired);
  if (provesCode) return provesCode;
  if (!("does_not_prove" in claims)) return "invalid_disclosure_structure";
  const dnpCode = _validateClaimArray(
    claims.does_not_prove,
    _REQUIRED_DOES_NOT_PROVE_CODES
  );
  if (dnpCode) return dnpCode;

  return null;
}

/**
 * Verify a satsignal.disclosure.v1 block end-to-end.
 *
 * @param {Object} disclosureBlock - the parsed `manifest.disclosure`.
 * @param {Object} opts
 * @param {?Uint8Array} opts.carrierBytes - raw bytes of the
 *   linked_anchor carrier canonical.json AS STORED (NOT re-canonicalized).
 *   null/undefined => `linked_anchor_carrier_missing`.
 * @param {?string} opts.onChainCommit - the on-chain document_hash at
 *   linked_anchor.txid, lowercase hex. Compared against the FIRST
 *   `onChainCommit.length` hex chars of sha256(carrierBytes), so this
 *   works for both the live 40-hex (20-byte) on-chain commitment and the
 * corpus's full 64-hex hash (0027 §4).
 * @param {?Uint8Array} [opts.viewBytes] - rendered presentation artifact
 *   bytes; optional §7 step 5 view-hash check.
 * @returns {Promise<{ok: boolean, fail_code: ?string}>}
 */
export async function verifyDisclosureCore(
  disclosureBlock,
  { carrierBytes, onChainCommit, viewBytes } = {}
) {
  // ── §7 step 1 — version literal ──────────────────────────────────
  if (
    disclosureBlock === null ||
    typeof disclosureBlock !== "object" ||
    Array.isArray(disclosureBlock)
  ) {
    return fail("invalid_disclosure_structure");
  }
  if (disclosureBlock.version !== _DISCLOSURE_VERSION_LITERAL) {
    return fail("unsupported_disclosure_version");
  }

  // ── structural validation ────────────────────────────────────────
  const structuralCode = _structuralFailCode(disclosureBlock);
  if (structuralCode) return fail(structuralCode);

  const linkedAnchor = disclosureBlock.linked_anchor;
  const revealed = disclosureBlock.revealed;
  const subjectProfile = linkedAnchor.subject_profile;
  const assertedRootHex = linkedAnchor.root;

  // ── §4 step 1 — locate the carrier ───────────────────────────────
  if (carrierBytes == null) {
    return fail("linked_anchor_carrier_missing");
  }

  // ── §4 step 2 — bind carrier to on-chain commitment ──────────────
  // Hash the carrier AS STORED. Compare at the commitment's width: the
  // on-chain value is the 20-byte (40-hex) PREFIX of the doc hash, while
  // the corpus supplies a full 64-hex hash. Slicing to the commitment
  // length is correct for both.
  //
  // Defense-in-depth: validate the commit BEFORE the prefix compare. An
  // empty (or too-short) commit would otherwise satisfy the slice compare
  // VACUOUSLY — `carrierShaHex.slice(0, 0) === ""` — and bind ANY carrier
  // to the chain. Require a non-empty lowercase-hex string of at least
  // _MIN_ONCHAIN_COMMIT_HEX_LEN chars. This is the §B.2 binding-failure
  // surface, so it reuses linked_anchor_canonical_hash_mismatch (no new
  // CONFORMANCE code).
  if (
    !isStr(onChainCommit) ||
    onChainCommit.length < _MIN_ONCHAIN_COMMIT_HEX_LEN ||
    !_ONCHAIN_COMMIT_HEX_RE.test(onChainCommit)
  ) {
    return fail("linked_anchor_canonical_hash_mismatch");
  }
  const carrierShaHex = await sha256Hex(carrierBytes);
  if (carrierShaHex.slice(0, onChainCommit.length) !== onChainCommit) {
    return fail("linked_anchor_canonical_hash_mismatch");
  }

  // ── parse carrier ────────────────────────────────────────────────
  let carrierDoc;
  try {
    carrierDoc = JSON.parse(new TextDecoder("utf-8").decode(carrierBytes));
  } catch (_e) {
    return fail("invalid_disclosure_structure");
  }
  const chunkMerkle =
    carrierDoc &&
    carrierDoc.subject &&
    carrierDoc.subject.proofs &&
    carrierDoc.subject.proofs.chunk_merkle;
  if (
    !chunkMerkle ||
    typeof chunkMerkle !== "object" ||
    Array.isArray(chunkMerkle)
  ) {
    return fail("invalid_disclosure_structure");
  }

  // ── §4 step 3 — root binding ─────────────────────────────────────
  if (chunkMerkle.root !== assertedRootHex) {
    return fail("linked_anchor_root_mismatch");
  }

  // ── §4 step 4 — profile binding ──────────────────────────────────
  if (chunkMerkle.scheme !== subjectProfile) {
    return fail("linked_anchor_profile_mismatch");
  }

  // ── §4 step 5 — algo binding ─────────────────────────────────────
  // Accepted-algo set resolved by the (subjectProfile, algo) pair
  // (csv-row-v1.md §5b / 0029 §1, §6): "sha256" for every implemented
  // profile; the SEALED "merkle-hmac-sha256" for every native profile whose
  // sealed rule is FROZEN — all four {csv-row-v1, csv-column-v1,
  // text-line-v1, json-keypath-v1} (gated on _NATIVE_SEALED_PROFILES;
  // csv-column-v1 sealed §5b frozen by decision 0041 Option B). The sealed
  // algo on a NON-sealed profile fails closed here. Mirrors verifier.py §4
  // step 5. `isNative` (the broader set) still drives the native STANDARD
  // recompute path below.
  const carrierAlgo = chunkMerkle.algo;
  const isNative = _NATIVE_PROFILES.has(subjectProfile);
  const sealedSupported = _NATIVE_SEALED_PROFILES.has(subjectProfile);
  const algoOk =
    carrierAlgo === "sha256" ||
    (sealedSupported && carrierAlgo === _NATIVE_SEALED_ALGO);
  if (!algoOk) {
    return fail("unsupported_linked_algo");
  }

  // ── §7 step 3 — pin profile (fail-closed; NEVER silent-skip) ──────
  if (!_IMPLEMENTED_PROFILES.has(subjectProfile)) {
    return fail("unsupported_profile");
  }

  // ── §7 step 4 — per-revealed-leaf recompute ──────────────────────
  // Resolve the leaf rule via the (subjectProfile, algo) pair
  // (csv-row-v1.md §5b / 0029 §1) — same rule for every native profile
  // {csv-row-v1, text-line-v1, json-keypath-v1}:
  //   - native profile + algo "sha256" -> UNSALTED bare-sha256;
  //   - native profile + algo "merkle-hmac-sha256" -> SEALED HMAC
  // leaf under the published per-leaf salt;
  //   - salted dotted profile -> the salted preimage path (leafHash).
  // `isNative` + `carrierAlgo` were resolved at §4 step 5; the algo gate
  // already rejected the sealed algo on any non-native profile.
  for (const entry of revealed) {
    const leafId = entry.leaf_id;
    const publishedLeafHash = entry.leaf_hash;
    const publishedProfile = entry.profile;
    const value = entry.value;
    const saltB64 = entry.salt_b64;
    const proofPath = entry.proof_path;

    // Native value->bytes rule: UTF-8 of the value string — the canonical
    // row for csv-row-v1 (§4), the canonical line for text-line-v1 (§4).
    // A non-string value cannot match the pinned leaf hash -> surfaces as
    // leaf_hash_mismatch.
    if (typeof value !== "string") {
      return fail("leaf_hash_mismatch");
    }
    const valueBytes = new TextEncoder().encode(value);

    let recomputed;
    if (isNative) {
      // Native profile (csv-row-v1 / text-line-v1 / json-keypath-v1):
      // sub-branch on the carrier algo (csv-row-v1.md §5b / 0029 §1, §3;
      // text-line-v1.md §5b / 0030; json-keypath-v1.md §5b / 0031). Both
      // modes share the value-bytes rule above.
      if (carrierAlgo === "sha256") {
        // STANDARD: bare sha256(utf8(value)). salt_b64 is ABSENT for this
        // mode (0029 §5) — do NOT read or require it.
        recomputed = await sha256Hex(valueBytes);
      } else {
        // SEALED (carrierAlgo === "merkle-hmac-sha256"; the algo gate
        // admitted only sha256 OR the sealed algo for native). The leaf
        // is HMAC-SHA256(base64decode(salt_b64), utf8(value)) under the
        // published PER-LEAF salt (csv-row-v1.md §5b.1).
        //
        // The carrier MUST pin salt_version "salt_v1"; a wrong/absent
        // salt_version is an unsupported sealed carrier ->
        // unsupported_linked_algo (mirrors verifier.py).
        if (chunkMerkle.salt_version !== _CSV_ROW_V1_SEALED_SALT_VERSION) {
          return fail("unsupported_linked_algo");
        }
        // salt_b64 is REQUIRED for sealed leaves (csv-row-v1.md §5b.1).
        // The structural schema treats it as OPTIONAL for csv-row-v1
        // (it cannot see the carrier algo), so the verifier enforces
        // presence here. A sealed leaf missing salt_b64 fails closed.
        if (saltB64 == null) {
          return fail("sealed_leaf_missing_salt");
        }
        let saltBytes;
        try {
          saltBytes = base64ToBytes(saltB64);
        } catch (_e) {
          return fail("leaf_hash_mismatch");
        }
        recomputed = await hmacSha256Hex(saltBytes, valueBytes);
      }
    } else {
      let saltBytes;
      try {
        saltBytes = base64ToBytes(saltB64);
      } catch (_e) {
        return fail("leaf_hash_mismatch");
      }
      try {
        recomputed = await leafHash(leafId, valueBytes, saltBytes);
      } catch (_e) {
        return fail("leaf_hash_mismatch");
      }
    }
    if (recomputed !== publishedLeafHash) {
      return fail("leaf_hash_mismatch");
    }

    // Walk proof_path to linked_anchor.root. verifyProofPath takes hex
    // strings and returns a boolean (throws on malformed hex/side, but
    // the structural validator already pinned hex64 + L/R above).
    let walks;
    try {
      walks = await verifyProofPath(publishedLeafHash, proofPath, assertedRootHex);
    } catch (_e) {
      return fail("merkle_path_mismatch");
    }
    if (!walks) {
      return fail("merkle_path_mismatch");
    }

    // Belt-and-braces: §7 step 4 final sub-bullet. The structural
    // validator catches this earlier, but a caller constructing a block
    // in-memory could bypass it.
    if (publishedProfile !== subjectProfile) {
      return fail("profile_mismatch");
    }
  }

  // ── §7 step 5 — view-hash check (optional) ───────────────────────
  const presentation = disclosureBlock.presentation;
  if (presentation != null && viewBytes != null) {
    const vsha = await sha256Hex(viewBytes);
    if (vsha !== presentation.view_sha256) {
      return fail("view_hash_mismatch");
    }
  }

  return ok();
}
