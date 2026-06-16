// disclosure-pack.mjs — shared, pure (Node-clean) glue for assembling a
// satsignal.disclosure.v1 .mbnt: base64url decoding, minimal JCS
// canonicalization, and the disclosure-.mbnt packer with the
// no-source-manifest strip rule.
//
// Decision 0023 mandates ONE JS source of truth. This module was lifted
// VERBATIM out of app.mjs (the only browser-coupled module) so that both
// app.mjs AND the in-repo redact SDK/CLI (0032) import the SAME glue
// instead of forking it. It touches no DOM and no globals beyond the
// platform atob (via base64.mjs) + TextEncoder, so it is importable under
// Node. Byte-behavior is identical to the former app.mjs inline code.

import { base64ToBytes } from "./base64.mjs";
import { buildMbnt, mbntMemberNames } from "./bundle.mjs";

/**
 * Decode a BASE64URL string (manifest master salt encoding) to bytes.
 * Pads to a multiple of 4 and maps the URL alphabet back to std base64,
 * then reuses base64ToBytes.
 * @param {string} b64url
 * @returns {Uint8Array}
 */
export function base64UrlToBytes(b64url) {
  let s = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4 !== 0) s += "=";
  return base64ToBytes(s);
}

/**
 * Minimal JCS canonicalization for the manifest shape (sorted keys,
 * compact separators) — equivalent to Python json.dumps(sort_keys=True,
 * separators=(",", ":")) for these shapes.
 */
export function jcsCanonicalize(value) {
  return JSON.stringify(value, sortKeysReplacer);
}
function sortKeysReplacer(_key, val) {
  if (val && typeof val === "object" && !Array.isArray(val)) {
    const sorted = {};
    for (const k of Object.keys(val).sort()) sorted[k] = val[k];
    return sorted;
  }
  return val;
}

/**
 * Assemble the disclosure .mbnt zip from a disclosure block + the carrier
 * canonical.json bytes.
 *
 * The carrier canonical.json is carried VERBATIM (the source .mbnt's
 * bytes) at the §4 spec path linked_anchor/canonical.json — NEVER
 * re-serialized.
 *
 * STRIP GUARD (0029 pt 8 / csv-row-v1.md §5b.1): the disclosure .mbnt
 * contains ONLY the disclosure manifest + the carrier at
 * linked_anchor/canonical.json. The SOURCE .mbnt manifest.json (which
 * holds the master salt for a sealed source) is NEVER passed to
 * buildMbnt — only `manifest` (the disclosure block) and
 * `linkedAnchorCanonical` (the carrier) are supplied here. Asserting it
 * explicitly keeps the no-source-manifest invariant load-bearing.
 *
 * @param {{disclosureBlock: object, carrierBytes: Uint8Array}} args
 * @returns {Uint8Array} the disclosure .mbnt zip bytes
 */
export function packDisclosureMbnt({ disclosureBlock, carrierBytes }) {
  const manifestBytes = new TextEncoder().encode(
    jcsCanonicalize({ disclosure: disclosureBlock, mbnt_version: "2.0" })
  );
  const mbntEntries = {
    manifest: manifestBytes,
    linkedAnchorCanonical: carrierBytes,
  };
  const out = buildMbnt(mbntEntries);
  // W1 (defense-in-depth): assert the invariant on the EMITTED bytes, not
  // just the construction above. The prior `if ("proofs" in mbntEntries)`
  // guard inspected the literal object's keys — which are always exactly
  // `manifest`/`linkedAnchorCanonical`, so it could never fire. Walking the
  // produced zip's central directory instead keeps the no-source-leaf-set /
  // master-salt-strip invariant load-bearing even if buildMbnt or the entry
  // construction changes (a stray proofs.json / root canonical.json / source
  // manifest would re-expose the source leaf-set or master salt).
  assertDisclosureMbntMembers(out);
  return out;
}

/**
 * The ONLY zip members a disclosure .mbnt may carry: the disclosure
 * manifest and the verbatim carrier doc at its §4 spec path. (The disclosure
 * manifest.json holds only the disclosure block + revealed per-leaf HKDF
 * salts — never the source master salt; the source .mbnt's manifest.json is
 * never passed to buildMbnt.)
 */
export const DISCLOSURE_MBNT_MEMBERS = Object.freeze([
  "manifest.json",
  "linked_anchor/canonical.json",
]);

/**
 * Assert a disclosure .mbnt's EMITTED member set is exactly the allowed two.
 * Throws if any disallowed member is present (e.g. root `canonical.json` or
 * `proofs.json`, which would re-expose the source leaf-set, or a stray
 * source `manifest`) or if a required member is missing.
 *
 * @param {Uint8Array} zipBytes
 */
export function assertDisclosureMbntMembers(zipBytes) {
  const members = mbntMemberNames(zipBytes);
  const allowed = new Set(DISCLOSURE_MBNT_MEMBERS);
  for (const name of members) {
    if (!allowed.has(name)) {
      throw new Error(
        `disclosure .mbnt emitted a disallowed member ${JSON.stringify(name)}; `
        + `only ${DISCLOSURE_MBNT_MEMBERS.join(", ")} are permitted `
        + `(a stray proofs.json / root canonical.json / source manifest would `
        + `re-expose the source leaf-set or master salt)`
      );
    }
  }
  for (const required of DISCLOSURE_MBNT_MEMBERS) {
    if (!members.includes(required)) {
      throw new Error(
        `disclosure .mbnt is missing required member ${JSON.stringify(required)}`
      );
    }
  }
}
