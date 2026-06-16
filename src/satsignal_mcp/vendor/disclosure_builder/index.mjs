// index.mjs — the public surface of satsignal-disclosure-redact.
//
// This module RE-EXPORTS the in-repo pure disclosure-builder ES modules
// UNCHANGED (decision 0023 — one JS source of truth). It NEVER copies,
// forks, or transpiles them. All cryptography lives in the re-exported
// modules; this package adds only Node file-I/O glue (redact-from-mbnt.mjs)
// and a zero-dependency .mbnt reader (mbnt-read.mjs).
//
// Node's package `exports` field cannot point outside the package dir
// (ERR_INVALID_PACKAGE_TARGET on a `../` escape), so `exports` maps only
// "." -> ./index.mjs. This in-package module then uses RELATIVE imports
// to escape into src/.../disclosure-builder/ — relative specifiers are
// allowed to cross the package boundary in-repo. On extraction / npm
// publish these relative paths must be repointed at a vendored snapshot
// (DEFERRED per decision 0032; package.json is private:true until then).
//
// NOTE: app.mjs is intentionally NOT re-exported — it is browser-coupled
// (touches `document`). The native leaf modules are pulled in
// transitively by redact-core.mjs.

const DB = "../../src/satsignal_notary/web/static/disclosure-builder";

// --- required core re-exports ---------------------------------------
export {
  buildRedactDisclosure,
  RedactBindingError,
  DISCLOSURE_VERSION,
} from "./redact-core.mjs";

export { verifyDisclosureCore } from "./verify-disclosure.mjs";

export { buildMbnt } from "./bundle.mjs";

export {
  base64UrlToBytes,
  jcsCanonicalize,
  packDisclosureMbnt,
} from "./disclosure-pack.mjs";

// --- cheap primitive re-exports (convenience for downstream callers) -
export {
  merkleRoot,
  merkleRootDuplicateLast,
  buildProofPathDuplicateLast,
  verifyProofPath,
} from "./merkle.mjs";

export {
  bytesToHex,
  hexToBytes,
} from "./hex.mjs";

export {
  bytesToBase64,
  base64ToBytes,
} from "./base64.mjs";

// --- this package's own additions -----------------------------------
export {
  redactFromMbnt,
  listMbntLeaves,
  parseSourceMembers,
  resolveRevealNames,
} from "./redact-from-mbnt.mjs";
export { readMbntMembers } from "./mbnt-read.mjs";

// SEALED deep-content anchor side (symmetric to the redact side):
// envelope builders + the Node I/O + HTTP wrapper.
export {
  buildSealedTextTreeEnvelope,
  buildSealedJsonAstEnvelope,
  buildSealedEnvelope,
} from "./anchor-pack.mjs";
export { anchorToMbnt, granularityForExt } from "./anchor-to-mbnt.mjs";

// (DB constant above is documentation of the re-export root; unused at
// runtime but kept so the path is greppable in one place.)
void DB;
