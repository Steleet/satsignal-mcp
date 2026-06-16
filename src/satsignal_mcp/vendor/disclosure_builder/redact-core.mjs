// redact-core.mjs — the PURE, node-testable redact-from-original core
// (standard + sealed / 0029 pt 4 + pt 8). Takes
// ALREADY-PARSED inputs (no DOM, no jszip, no fetch, no anchor step) and
// produces a validated redacted copy + a satsignal.disclosure.v1
// disclosure block whose revealed[] binds to the EXISTING anchor's native
// csv-row-v1 chunk_merkle.
//
// The browser glue (app.mjs) does file I/O + zip extraction and then
// calls buildRedactDisclosure() with parsed inputs; tests drive the same
// pure function directly. This keeps the close-critical logic out from
// behind browser-only APIs.
//
// TWO MODES, branched on the carrier chunk_merkle.algo (0029 §1):
//   - "sha256" (STANDARD): unsalted bare-sha256 leaf; revealed[] carries
// NO salt_b64; no master salt anywhere (standard path, UNCHANGED).
//   - "merkle-hmac-sha256" (SEALED): per-leaf HKDF-salt HMAC leaf. The
//     caller passes the 32-byte MASTER salt (read from the SOURCE .mbnt
//     manifest.json). The core derives the per-leaf salts of the REVEALED
//     rows only, emits each revealed[].salt_b64 = its PER-LEAF salt, and
//     STRIPS the master salt from ALL output (0029 pt 8 / csv-row-v1.md
//     §5b.1 — THE MASTER-SALT-STRIP RULE, forever). The master salt is
//     used ONLY for derivation; it never appears in the disclosure block,
//     the redacted copy, the carrier, or anywhere this core returns.
//
// Pipeline (0029 pt 4 + pt 8):
//   a. recompute the native data-row leaves from originalFileBytes
//      (standard: sha256; sealed: HKDF per-leaf salt + HMAC, keyed by the
//      master salt);
//   b. HARD-FAIL if recomputed leaves != proofsJson.merkle_leaves OR the
//      recomputed duplicate-last root != canonicalJson chunk_merkle.root
//      (distinct, testable RedactBindingError — wrong file / wrong master
//      salt / wrong bundle pair);
//   c. for each SELECTED row build a DUPLICATE-LAST proof_path over the
//      committed merkle_leaves;
//   d. assemble the disclosure block (linked_anchor + revealed[] + claims
//      + presentation); standard: NO salt_b64; sealed: revealed[].salt_b64
//      = the REVEALED row's PER-LEAF salt ONLY (never the master, never a
//      redacted row's per-leaf salt);
//   e. produce the redacted-copy bytes (header preserved; redacted rows
//      replaced by the marker, positions preserved) + presentation
//      {format, view_sha256: sha256(redacted bytes), ...}.
//
// carrier canonical.json is carried VERBATIM by the glue (app.mjs) — this
// core never re-serializes it.

import * as csvNative from "./csv-row-v1-native.mjs";
import * as csvColumnNative from "./csv-column-v1-native.mjs";
import * as textNative from "./text-line-v1-native.mjs";
import * as jsonNative from "./json-keypath-v1-native.mjs";
import * as jsonAstNative from "./json-ast-v1-native.mjs";
import * as textTreeNative from "./text-tree-v1-native.mjs";
import {
  merkleRootDuplicateLast,
  buildProofPathDuplicateLast,
} from "./merkle.mjs";
import { bytesToHex } from "./hex.mjs";
import { bytesToBase64 } from "./base64.mjs";

export const DISCLOSURE_VERSION = "satsignal.disclosure.v1";
const REDACTION_MARKER = "[REDACTED]";

// The sealed-mode carrier algo + salt_version literals are shared across
// every native profile (the anchor's sealed merkle assembly is generic),
// so either native module exports the same constants.
const SEALED_ALGO = csvNative.SEALED_ALGO;
const SEALED_SALT_VERSION = csvNative.SEALED_SALT_VERSION;

/**
 * Render a line-oriented redacted copy: header (if any) preserved
 * verbatim, then each leaf emitted as its canonical value (revealed) or
 * the redaction marker (redacted) — positions preserved, `\n`-joined, no
 * trailing newline (the canonical doc shape). Shared by every line/row
 * native profile (csv-row-v1 has a header; text-line-v1 does not, so its
 * headerRow is null and the header line is skipped).
 * @param {{headerRow: ?string, dataRows: string[], selected: Set<number>}} a
 * @returns {Uint8Array}
 */
function _renderLineOriented({ headerRow, dataRows, selected }) {
  const lines = [];
  if (headerRow != null) lines.push(headerRow);
  for (let i = 0; i < dataRows.length; i++) {
    lines.push(selected.has(i) ? dataRows[i] : REDACTION_MARKER);
  }
  return new TextEncoder().encode(lines.join("\n"));
}

/**
 * Render a COLUMN-projected redacted CSV grid (0040). The header row is
 * preserved verbatim; then every data row is re-emitted with each REVEALED
 * column's cell shown and each WITHHELD column's cell replaced by the
 * redaction marker — positions preserved, a readable CSV. `selected` is a
 * Set of COLUMN indices. Uses `columnsCells` (the per-column RAW data cells)
 * — NOT `dataRows` (which are LF-joined column values that can't be re-split
 * safely). Presentation-only: feeds presentation.view_sha256, never an
 * on-chain hash (the column leaf value canon is unaffected).
 * @param {{headerRow: ?string, columnsCells: string[][], selected: Set<number>}} a
 * @returns {Uint8Array}
 */
function _renderColumnOriented({ headerRow, columnsCells, selected }) {
  const lines = [];
  if (headerRow != null) lines.push(headerRow);
  const nrows = columnsCells.length ? columnsCells[0].length : 0;
  for (let i = 0; i < nrows; i++) {
    const cells = columnsCells.map((col, j) =>
      selected.has(j) ? col[i] : REDACTION_MARKER
    );
    lines.push(cells.map(csvNative.csvField).join(","));
  }
  return new TextEncoder().encode(lines.join("\n"));
}

/** DROP-key JSON render (0031): canonical JCS object of ONLY the
 * revealed keys; withheld keys absent. dataRows are sorted-key entry strings.*/
function _renderJsonDropKey({ dataRows, selected }) {
  const entries = [];
  for (let i = 0; i < dataRows.length; i++) if (selected.has(i)) entries.push(dataRows[i]);
  return new TextEncoder().encode("{" + entries.join(",") + "}");
}
/** MASK-value JSON render (0031): canonical JSON object with ALL
 * keys; revealed keep their entry, withheld become "key":"[REDACTED]". */
function _renderJsonMask({ dataRows, selected, canonicalKeys }) {
  const REDACTED_VALUE = JSON.stringify("[REDACTED]");  // -> "\"[REDACTED]\""
  const out = [];
  for (let i = 0; i < dataRows.length; i++) {
    out.push(selected.has(i) ? dataRows[i] : (canonicalKeys[i] + ":" + REDACTED_VALUE));
  }
  return new TextEncoder().encode("{" + out.join(",") + "}");
}

/** DROP json-ast render (0042): the canonical JCS DOCUMENT reconstructed
 * from the REVEALED nodes — each revealed node's value placed at its
 * RFC-6901 pointer, then JCS-canonicalized; withheld nodes absent. Reuses
 * the SAME jcsCanonicalize as the anchor (no drift). Presentation-only — it
 * feeds presentation.view_sha256 ONLY; the proof binds the LEAVES, not the
 * view. Intermediate containers are reconstructed as objects (a revealed
 * array index under an unrevealed array renders as an object key — a known,
 * crypto-neutral presentation quirk; reveal a whole subtree for a faithful
 * array). Revealing the root pointer "" yields the whole canonical document.
 */
function _renderJsonAstDrop({ selected, pointers, nodeValues }) {
  let rootValue;
  let rootSet = false;
  let tree = {};
  for (let i = 0; i < pointers.length; i++) {
    if (!selected.has(i)) continue;
    const ptr = pointers[i];
    const val = nodeValues[i];
    if (ptr === "") { rootValue = val; rootSet = true; continue; }
    const segs = ptr
      .split("/")
      .slice(1)
      .map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"));
    let cur = tree;
    for (let s = 0; s < segs.length - 1; s++) {
      const k = segs[s];
      if (cur[k] == null || typeof cur[k] !== "object") cur[k] = {};
      cur = cur[k];
    }
    cur[segs[segs.length - 1]] = val;
  }
  const out = rootSet ? rootValue : tree;
  return new TextEncoder().encode(jsonNative.jcsCanonicalize(out));
}

/** RFC-6901 reference-token encoding for an object key — NFC, then `~`->`~0`
 * and `/`->`~1`. A local mirror of json-ast-v1-native.mjs:escapeRfc6901 (which
 * is module-private there) so the pointers _renderJsonAstMask reconstructs as
 * it walks the parsed document are byte-identical to the committed leaf
 * pointers. The two special characters are ASCII so NFC never changes them;
 * `~` is escaped before `/` (RFC-6901 order). */
function _escapeRfc6901Token(key) {
  return key.normalize("NFC").replace(/~/g, "~0").replace(/\//g, "~1");
}

/** MASK json-ast render (0042 fast-follow): reconstruct the FULL canonical
 * document, with each node shown as its real value when COVERED (its own leaf
 * is selected, OR any ANCESTOR's subtree leaf is selected) and as the
 * "[REDACTED]" marker string when withheld. Unlike _renderJsonAstDrop (which
 * places ONLY the revealed nodes and omits everything else), this walks the
 * WHOLE parsed document top-down from the root value and preserves the original
 * shape (objects/arrays/keys/indices), flipping only withheld leaf values to
 * the marker. A FULLY-withheld container (no covered descendant) collapses to a
 * single "[REDACTED]" (it is not recursed — so its keys/length stay hidden); a
 * PARTIALLY-revealed container is recursed with markers at its withheld leaves
 * (positions preserved). Revealing the root pointer "" yields the whole
 * document verbatim. Presentation-only — feeds presentation.view_sha256 ONLY;
 * the proof binds the LEAVES, not the view. Reuses the SAME jcsCanonicalize as
 * the anchor (no canon drift). */
function _renderJsonAstMask({ selected, pointers, nodeValues }) {
  const JSON_REDACTION_MARKER = "[REDACTED]";
  const selectedPointers = [];
  let rootValue;
  for (let i = 0; i < pointers.length; i++) {
    if (pointers[i] === "") rootValue = nodeValues[i];
    if (selected.has(i)) selectedPointers.push(pointers[i]);
  }
  // Covered: the node itself, or any ANCESTOR subtree leaf, is revealed.
  const isCovered = (ptr) => {
    for (const sp of selectedPointers) {
      if (sp === "") return true; // root revealed -> the whole document
      if (ptr === sp || ptr.startsWith(sp + "/")) return true;
    }
    return false;
  };
  // Whether any leaf strictly inside this subtree is selected (so a withheld
  // container is recursed rather than collapsed to a single marker).
  const subtreeHasSelected = (ptr) => {
    const prefix = ptr + "/";
    for (const sp of selectedPointers) {
      if (sp === ptr || sp.startsWith(prefix)) return true;
    }
    return false;
  };
  const build = (value, ptr) => {
    if (isCovered(ptr)) return value; // revealed: the whole subtree verbatim
    if (value !== null && typeof value === "object") {
      if (!subtreeHasSelected(ptr)) return JSON_REDACTION_MARKER; // collapse
      if (Array.isArray(value)) {
        return value.map((el, k) => build(el, ptr + "/" + String(k)));
      }
      const out = {};
      for (const k of Object.keys(value)) {
        out[k] = build(value[k], ptr + "/" + _escapeRfc6901Token(k));
      }
      return out;
    }
    return JSON_REDACTION_MARKER; // withheld primitive
  };
  return new TextEncoder().encode(
    jsonNative.jcsCanonicalize(build(rootValue, ""))
  );
}

// ── text-tree-v1 renderers (decision 0045) ───────────────────────────
// Multi-level text: nodes are the file (""), paragraphs (/pN), sentences
// (/pN/sM), tokens (/pN/sM/tK). `paths` (sorted-path order, = the leaf order)
// + `spans` (each node's exact canonical content) come from the native module.
// Presentation-only — feeds presentation.view_sha256 ONLY; the proof binds the
// LEAVES, not the view.

/** Parse "/p0/s1/t2" → [["p",0],["s",1],["t",2]]; "" → []. Document order
 * among siblings is ASCENDING numeric component (NOT the lexicographic
 * sorted-path leaf order, which mis-orders /p10 vs /p2). */
function _ttSegs(path) {
  if (path === "") return [];
  return path.slice(1).split("/").map((seg) => [seg[0], parseInt(seg.slice(1), 10)]);
}
/** Build a path→{span, selected} index + a parent→ordered-children map +
 * a "subtree has a selected node" test, from the flat node lists. */
function _ttTree(paths, spans, selected) {
  const node = new Map(); // path -> {span, selected}
  const kids = new Map(); // parent path -> [child path]
  for (let i = 0; i < paths.length; i++) {
    node.set(paths[i], { span: spans[i], selected: selected.has(i) });
    if (paths[i] === "") continue;
    const segs = _ttSegs(paths[i]);
    const parent = segs.length === 1 ? "" : "/" + segs.slice(0, -1).map(([t, n]) => t + n).join("/");
    if (!kids.has(parent)) kids.set(parent, []);
    kids.get(parent).push(paths[i]);
  }
  // Order each sibling list by document order (ascending last numeric segment).
  for (const arr of kids.values()) {
    arr.sort((a, b) => _ttSegs(a).at(-1)[1] - _ttSegs(b).at(-1)[1]);
  }
  const subtreeHasSelected = (path) => {
    const n = node.get(path);
    if (n && n.selected) return true;
    for (const k of kids.get(path) || []) if (subtreeHasSelected(k)) return true;
    return false;
  };
  return { node, kids, subtreeHasSelected };
}
/** Walk the tree top-down emitting a flat list of segments — either a revealed
 * node's exact span, or a withheld MARKER. A revealed node emits its span
 * verbatim (the whole subtree); a withheld leaf (token / empty container) emits
 * one marker; a partially-revealed container recurses. The caller coalesces
 * consecutive markers. (Inter-token whitespace is not a node, so it rides with
 * the enclosing sentence span when that span is revealed, and is dropped when
 * only a token is revealed — the privacy-first drop contract.) */
function _ttCollect(path, t, out) {
  const n = t.node.get(path);
  if (n && n.selected) { out.push({ text: n.span }); return; }
  const kids = t.kids.get(path) || [];
  if (kids.length === 0) { out.push({ marker: true }); return; } // withheld leaf
  for (const k of kids) {
    if (t.subtreeHasSelected(k)) _ttCollect(k, t, out);
    else out.push({ marker: true });
  }
}
function _ttRender(paths, spans, selected, marker) {
  const t = _ttTree(paths, spans, selected);
  const segs = [];
  _ttCollect("", t, segs);
  let out = "";
  let prevMarker = false;
  for (const s of segs) {
    if (s.marker) { if (!prevMarker) out += marker; prevMarker = true; }
    else { out += s.text; prevMarker = false; }
  }
  return new TextEncoder().encode(out);
}
/** DROP text-tree render (0045): revealed nodes' spans in document order;
 * each maximal withheld run collapses to a single "[…]" (positions_hidden). */
function _renderTextTreeDrop({ selected, paths, spans }) {
  return _ttRender(paths, spans, selected, "[…]");
}
/** MASK text-tree render (0045 fast-follow): same walk, withheld runs shown as
 * "[REDACTED]" in position (positions_preserved). */
function _renderTextTreeMask({ selected, paths, spans }) {
  return _ttRender(paths, spans, selected, "[REDACTED]");
}

// ── Profile strategy table (0030 pt 4 / 0031 pt — Stage 7) ───────────
// Keyed by the carrier `chunk_merkle.scheme`. Each strategy ports ONE
// anchor file-type's native leaf rule + redacted-copy rendering:
//   - computeLeaves / computeSealedLeaves / encodeLeafId come from the
//     per-profile native module (the byte-for-byte anchor canon);
//   - rendering + presentation are profile-local.
// Two presentation shapes:
//   - SINGLE-MODE (csv-row-v1, text-line-v1): one renderRedactedCopy +
//     fixed redactionMarker ("[REDACTED]") + structureDisclosure
//     ("positions_preserved"). These are the original line-oriented
//     byte-identical rules — NEVER change them.
//   - MULTI-MODE (json-keypath-v1): a `modes` map + `defaultMode`. The
//     OWNER decision (0031) ships BOTH JSON renderings; the user picks
//     per disclosure (default = drop). Rendering is presentation-only —
//     the proof binds each revealed key's leaf into the merkle root; the
//     redacted copy's bytes feed only presentation.view_sha256, never an
//     on-chain hash — so withheld-key DISPLAY changes nothing crypto:
//       - drop (DEFAULT, privacy-first): canonical JCS object of ONLY the
//         revealed keys (positions_hidden, "(key omitted)");
//       - mask (text-line analog): all keys, withheld → "key":"[REDACTED]"
//         (positions_preserved, "[REDACTED]").
// `format` is the presentation.format literal (a _PRESENTATION_FORMATS
// member: "csv" | "txt" | "json"). Adding a profile = one entry here + its
// native module + verifier registration + a frozen corpus (0030/0031).
const _STRATEGIES = {
  "csv-row-v1": {
    profile: "csv-row-v1",
    computeLeaves: csvNative.computeNativeLeaves,
    computeSealedLeaves: csvNative.computeSealedLeaves,
    encodeLeafId: csvNative.encodeLeafId,
    format: "csv",
    renderRedactedCopy: _renderLineOriented,
    redactionMarker: REDACTION_MARKER,
    structureDisclosure: "positions_preserved",
  },
  "csv-column-v1": {
    profile: "csv-column-v1",
    computeLeaves: csvColumnNative.computeNativeLeaves,
    computeSealedLeaves: csvColumnNative.computeSealedLeaves,
    encodeLeafId: csvColumnNative.encodeLeafId,
    format: "csv",
    renderRedactedCopy: _renderColumnOriented,
    redactionMarker: REDACTION_MARKER,
    structureDisclosure: "positions_preserved",
    // claims wording: a column disclosure reveals/withholds COLUMNS (matches
    // the frozen CC1 fixture text). Other profiles default to "row".
    claimsNoun: "column",
  },
  "text-line-v1": {
    profile: "text-line-v1",
    computeLeaves: textNative.computeNativeLeaves,
    computeSealedLeaves: textNative.computeSealedLeaves,
    encodeLeafId: textNative.encodeLeafId,
    // presentation.format MUST be a manifest_schema _PRESENTATION_FORMATS
    // member: text uses "txt" (NOT "text").
    format: "txt",
    renderRedactedCopy: _renderLineOriented,
    redactionMarker: REDACTION_MARKER,
    structureDisclosure: "positions_preserved",
  },
  "json-keypath-v1": {
    profile: "json-keypath-v1",
    computeLeaves: jsonNative.computeNativeLeaves,
    computeSealedLeaves: jsonNative.computeSealedLeaves,
    encodeLeafId: jsonNative.encodeLeafId,
    format: "json",
    defaultMode: "drop",
    modes: {
      drop: { render: _renderJsonDropKey, redactionMarker: "(key omitted)", structureDisclosure: "positions_hidden" },
      mask: { render: _renderJsonMask,    redactionMarker: "[REDACTED]",    structureDisclosure: "positions_preserved" },
    },
  },
  // json-ast-v1 (decision 0042): deep-field JSON, SEALED ONLY (a standard
  // carrier is rejected at anchor submit, so computeLeaves is unreachable in
  // production but present for interface symmetry). MULTI-MODE, like
  // json-keypath-v1:
  //   - drop (DEFAULT): reconstructed canonical doc of ONLY the revealed nodes
  //     (positions_hidden, "(key omitted)"). The core default MUST stay "drop"
  //     — the modeless verifier roundtrip (tests/verifier/
  //     test_disclosure_json_ast_native_sealed.mjs) asserts the frozen S1
  //     view_sha256, which is the DROP render. Do not flip this.
  //   - mask: the full document reconstructed with withheld nodes shown as
  //     "[REDACTED]" (positions_preserved). This is the builder UI's default
  //     (state.renderMode = "mask"), passed explicitly — distinct from the
  //     core defaultMode above.
  // Presentation-only — both modes verify into the SAME sealed root; the
  // redacted view feeds presentation.view_sha256, never an on-chain hash.
  "json-ast-v1": {
    profile: "json-ast-v1",
    computeLeaves: jsonAstNative.computeNativeLeaves,
    computeSealedLeaves: jsonAstNative.computeSealedLeaves,
    encodeLeafId: jsonAstNative.encodeLeafId,
    format: "json",
    defaultMode: "drop",
    modes: {
      drop: { render: _renderJsonAstDrop, redactionMarker: "(key omitted)", structureDisclosure: "positions_hidden" },
      mask: { render: _renderJsonAstMask, redactionMarker: "[REDACTED]",    structureDisclosure: "positions_preserved" },
    },
    claimsNoun: "node",
  },
  // text-tree-v1 (decision 0045): multi-level text, SEALED ONLY (standard
  // carriers are rejected at submit, so computeLeaves is unreachable in
  // production but present for interface symmetry). MULTI-MODE:
  //   - drop (DEFAULT): revealed nodes' spans in document order, each maximal
  //     withheld run collapsed to "[…]" (positions_hidden). The modeless
  //     verifier roundtrip (tests/verifier/test_disclosure_text_tree_native_
  //     sealed.mjs) asserts the frozen S1 view_sha256, which is the DROP render.
  //   - mask: same walk, withheld runs shown as "[REDACTED]" in position.
  // Presentation-only — both modes verify into the SAME sealed root.
  "text-tree-v1": {
    profile: "text-tree-v1",
    computeLeaves: textTreeNative.computeNativeLeaves,
    computeSealedLeaves: textTreeNative.computeSealedLeaves,
    encodeLeafId: textTreeNative.encodeLeafId,
    format: "txt",
    defaultMode: "drop",
    modes: {
      drop: { render: _renderTextTreeDrop, redactionMarker: "[…]",        structureDisclosure: "positions_hidden" },
      mask: { render: _renderTextTreeMask, redactionMarker: "[REDACTED]", structureDisclosure: "positions_preserved" },
    },
    claimsNoun: "node",
  },
};

/**
 * Resolve the profile strategy for a carrier `chunk_merkle.scheme`, or
 * null if this tool does not bind to that scheme. Exposed so the browser
 * glue (app.mjs) can route its early row-preview recompute through the
 * SAME compute functions the pure core uses (one source of truth).
 * @param {string} scheme
 * @returns {?{profile:string, computeLeaves:Function,
 *   computeSealedLeaves:Function, encodeLeafId:Function, format:string,
 *   renderRedactedCopy:Function}}
 */
export function getProfileStrategy(scheme) {
  return _STRATEGIES[scheme] || null;
}

/**
 * The carrier `chunk_merkle.scheme`s this tool can redact, for UI copy.
 * @returns {string[]}
 */
export function supportedSchemes() {
  return Object.keys(_STRATEGIES);
}

/**
 * Raised when the recomputed leaves/root do NOT match the carrier bundle
 * — i.e. the original file and the .mbnt are not a matching pair (or one
 * was tampered). Distinct from a generic error so the glue + tests can
 * surface a clear "wrong file / wrong bundle" message (0029 pt 4b).
 */
export class RedactBindingError extends Error {
  constructor(message, detail) {
    super(message);
    this.name = "RedactBindingError";
    this.detail = detail || null;
  }
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

function _isHex64(s) {
  return typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
}

/**
 * Read the committed chunk_merkle from a parsed carrier canonical.json
 * object. Handles schema_version 1 + 2 carrier shapes (both nest under
 * subject.proofs.chunk_merkle for CSV anchors).
 * @param {Object} canonicalJson
 * @returns {{scheme:string, algo:string, leaf_count:number, root:string}}
 */
function _readChunkMerkle(canonicalJson) {
  const cm =
    canonicalJson &&
    canonicalJson.subject &&
    canonicalJson.subject.proofs &&
    canonicalJson.subject.proofs.chunk_merkle;
  if (!cm || typeof cm !== "object" || Array.isArray(cm)) {
    throw new RedactBindingError(
      "carrier canonical.json has no subject.proofs.chunk_merkle — " +
        "not a per-chunk anchor bundle"
    );
  }
  return cm;
}

/**
 * The close-critical pure core. All inputs are already parsed.
 *
 * @param {Object} args
 * @param {Uint8Array} args.originalFileBytes - raw original CSV bytes.
 * @param {Object} args.canonicalJson - parsed carrier canonical.json
 *   (the committed chunk_merkle root/scheme/algo/leaf_count).
 * @param {Object} args.proofsJson - parsed proofs.json
 *   ({scheme, merkle_leaves:[hex...], metadata:{leaf_count}}).
 * @param {number[]|Set<number>} args.selectedLeafIndices - data-row
 *   indices to REVEAL (0-based). The rest are redacted.
 * @param {Object} args.anchorRef - {txid, bundle_id} read from the source
 *   .mbnt manifest/receipt by the glue.
 * @param {string} [args.disclosureId] - optional override; a default is
 *   synthesized when absent.
 * @param {string} [args.renderMode] - optional renderer selector for
 *   MULTI-MODE profiles (json-keypath-v1): "drop" (default) or "mask".
 *   IGNORED for single-mode profiles (csv-row-v1, text-line-v1) — never
 *   throws on an unused renderMode. Rendering is presentation-only and
 *   does not affect the proof or any on-chain hash (0031).
 * @param {Uint8Array} [args.masterSaltBytes] - REQUIRED for a SEALED
 *   source (carrier algo "merkle-hmac-sha256"): the 32-byte master salt
 *   read from the SOURCE .mbnt manifest.json salt_b64. Used ONLY to derive
 *   the per-leaf salts; STRIPPED from all output (0029 pt 8). MUST be
 *   absent/undefined for a standard source.
 * @returns {Promise<{disclosureBlock:Object, redactedCopyBytes:Uint8Array,
 *   dataRows:string[], leafHashes:string[], rootHex:string}>}
 * @throws {RedactBindingError} when the file/bundle do not match, the
 *   master salt is absent/wrong-length for a sealed source, or on bad
 *   selection / bad anchorRef.
 */
export async function buildRedactDisclosure({
  originalFileBytes,
  canonicalJson,
  proofsJson,
  selectedLeafIndices,
  anchorRef,
  disclosureId,
  masterSaltBytes,
  renderMode,
}) {
  // ── profile + algo dispatch (0029 §1 / 0030 pt 4): read the carrier's
  // committed scheme + algo FIRST so the leaf recompute uses the right
  // rule. The full chunk_merkle read + root/scheme/algo gates below stay
  // as the binding source of truth.
  const _chunkMerkle0 = _readChunkMerkle(canonicalJson);
  const _carrierScheme = _chunkMerkle0 && _chunkMerkle0.scheme;
  const strategy = _STRATEGIES[_carrierScheme];
  if (!strategy) {
    throw new RedactBindingError(
      `carrier chunk_merkle.scheme is ${JSON.stringify(_carrierScheme)}; ` +
        `this tool binds only to ${JSON.stringify(Object.keys(_STRATEGIES))}`,
      { scheme: _carrierScheme }
    );
  }
  const NATIVE_PROFILE = strategy.profile;
  const encodeLeafId = strategy.encodeLeafId;
  const computeNativeLeaves = strategy.computeLeaves;
  const computeSealedLeaves = strategy.computeSealedLeaves;
  const _carrierAlgo = _chunkMerkle0 && _chunkMerkle0.algo;
  const isSealed = _carrierAlgo === SEALED_ALGO;

  // ── a. recompute native leaves from the original file ────────────────
  // STANDARD: bare sha256 leaves, no salts. SEALED: per-leaf HKDF-salt
  // HMAC leaves keyed by the master salt. perLeafSalts is populated ONLY
  // in the sealed branch; for the revealed rows the caller (below) emits
  // its base64 — NEVER the master salt, NEVER a redacted row's salt.
  let headerRow;
  let dataRows;
  let leafHashes;
  let perLeafSalts = null;
  // canonicalKeys is surfaced ONLY by json-keypath-v1 (the MASK renderer
  // needs the quoted key literals); undefined for csv/text — harmless.
  let canonicalKeys;
  // columnsCells is surfaced ONLY by csv-column-v1 (the column grid renderer
  // needs the per-column raw cells); undefined for the other profiles.
  let columnsCells;
  // pointers + nodeValues are surfaced ONLY by json-ast-v1 (the deep-field
  // drop renderer reconstructs the canonical doc from the revealed nodes'
  // pointers + values); undefined for the other profiles.
  let pointers;
  let nodeValues;
  // paths + spans are surfaced ONLY by text-tree-v1 (the multi-level renderers
  // walk the node tree by slash-path with each node's exact span); undefined
  // for the other profiles.
  let paths;
  let spans;
  if (isSealed) {
    // SEALED requires the master salt. Hard-fail loudly when it is absent
    // or the wrong length — this is the gate that keeps a sealed source
    // from silently falling back to an unsalted recompute.
    if (
      !(masterSaltBytes instanceof Uint8Array) ||
      masterSaltBytes.length !== 32
    ) {
      throw new RedactBindingError(
        "sealed source requires the 32-byte master salt from manifest.json",
        { algo: _carrierAlgo, master_salt_len: masterSaltBytes && masterSaltBytes.length }
      );
    }
    // The carrier MUST pin salt_version "salt_v1" (csv-row-v1.md §5b).
    if (_chunkMerkle0.salt_version !== SEALED_SALT_VERSION) {
      throw new RedactBindingError(
        `sealed carrier salt_version is ${JSON.stringify(_chunkMerkle0.salt_version)}; ` +
          `this tool supports ${JSON.stringify(SEALED_SALT_VERSION)} only`,
        { salt_version: _chunkMerkle0.salt_version }
      );
    }
    ({ headerRow, dataRows, leafHashes, perLeafSalts, canonicalKeys,
       columnsCells, pointers, nodeValues, paths, spans } =
      await computeSealedLeaves(originalFileBytes, masterSaltBytes));
  } else {
    ({ headerRow, dataRows, leafHashes, canonicalKeys, columnsCells,
       pointers, nodeValues, paths, spans } =
      await computeNativeLeaves(originalFileBytes));
  }

  // ── b. HARD-FAIL on file/bundle mismatch (distinct error) ────────────
  const committedLeaves =
    proofsJson && Array.isArray(proofsJson.merkle_leaves)
      ? proofsJson.merkle_leaves
      : null;
  if (committedLeaves == null) {
    throw new RedactBindingError(
      "proofs.json has no merkle_leaves array"
    );
  }
  if (committedLeaves.length !== leafHashes.length) {
    throw new RedactBindingError(
      `leaf-count mismatch: the original file has ${leafHashes.length} ` +
        `data rows but the bundle commits ${committedLeaves.length} leaves. ` +
        "This original file and this .mbnt do not match.",
      { recomputed: leafHashes.length, committed: committedLeaves.length }
    );
  }
  for (let i = 0; i < leafHashes.length; i++) {
    if (leafHashes[i] !== committedLeaves[i]) {
      throw new RedactBindingError(
        `leaf ${i} (${encodeLeafId(i)}) does not match the committed ` +
          "merkle_leaves. This original file and this .mbnt do not match " +
          "(wrong file, edited file, or wrong bundle).",
        { index: i, recomputed: leafHashes[i], committed: committedLeaves[i] }
      );
    }
  }

  const chunkMerkle = _readChunkMerkle(canonicalJson);
  const committedRoot = chunkMerkle.root;
  if (!_isHex64(committedRoot)) {
    throw new RedactBindingError(
      "carrier chunk_merkle.root is not 64-hex"
    );
  }
  // Recompute the duplicate-last root from the (verified) leaves and bind
  // it to the carrier's committed root. This is the on-chain binding: the
  // verifier later proves each revealed leaf into THIS root.
  const recomputedRoot = await merkleRootDuplicateLast(leafHashes);
  if (recomputedRoot !== committedRoot) {
    throw new RedactBindingError(
      "recomputed duplicate-last merkle root does not match the bundle's " +
        "committed root. This original file and this .mbnt do not match.",
      { recomputed: recomputedRoot, committed: committedRoot }
    );
  }
  // Profile/algo gate: this core binds to scheme csv-row-v1 with EITHER
  // algo "sha256" (standard) OR "merkle-hmac-sha256" (sealed). The leaf
  // recompute above already dispatched on the algo; this gate fails any
  // other algo closed.
  if (chunkMerkle.scheme !== NATIVE_PROFILE) {
    throw new RedactBindingError(
      `carrier chunk_merkle.scheme is ${JSON.stringify(chunkMerkle.scheme)}; ` +
        `this tool binds only to ${JSON.stringify(NATIVE_PROFILE)}`,
      { scheme: chunkMerkle.scheme }
    );
  }
  if (chunkMerkle.algo !== "sha256" && chunkMerkle.algo !== SEALED_ALGO) {
    throw new RedactBindingError(
      `carrier chunk_merkle.algo is ${JSON.stringify(chunkMerkle.algo)}; ` +
        `this tool supports standard ("sha256") and sealed ` +
        `(${JSON.stringify(SEALED_ALGO)}) modes only`,
      { algo: chunkMerkle.algo }
    );
  }

  // ── selection ────────────────────────────────────────────────────────
  const selected =
    selectedLeafIndices instanceof Set
      ? selectedLeafIndices
      : new Set(selectedLeafIndices || []);
  for (const idx of selected) {
    if (!Number.isInteger(idx) || idx < 0 || idx >= leafHashes.length) {
      throw new RedactBindingError(
        `selected leaf index ${idx} out of range [0, ${leafHashes.length})`
      );
    }
  }
  if (selected.size === 0) {
    throw new RedactBindingError(
      "select at least one row to reveal"
    );
  }
  if (selected.size === leafHashes.length) {
    throw new RedactBindingError(
      "all rows selected — this is not a partial disclosure; redact at " +
        "least one row"
    );
  }

  // ── anchor reference ──────────────────────────────────────────────────
  const txid = anchorRef && anchorRef.txid;
  const bundleId = anchorRef && anchorRef.bundle_id;
  if (!_isHex64(txid)) {
    throw new RedactBindingError(
      "anchorRef.txid must be 64-hex (read it from the source .mbnt " +
        "manifest/receipt)"
    );
  }
  if (typeof bundleId !== "string" || bundleId.length === 0) {
    throw new RedactBindingError(
      "anchorRef.bundle_id must be a non-empty string (read it from the " +
        "source .mbnt manifest/receipt)"
    );
  }

  // ── c + d. build duplicate-last proof paths + revealed[] ─────────────
  // SEALED MASTER-SALT-STRIP (0029 pt 8 / csv-row-v1.md §5b.1 — forever):
  // for a sealed source we emit salt_b64 = the PER-LEAF salt of the
  // REVEALED row ONLY (std base64). The master salt is NEVER emitted (it
  // is only the HKDF IKM, used inside computeSealedLeaves). A redacted
  // row's per-leaf salt is NEVER emitted either — we skip non-selected
  // rows entirely below, so perLeafSalts[j] for an unrevealed j never
  // leaves this function. Standard mode emits NO salt_b64 (unsalted, §5).
  const revealed = [];
  for (let i = 0; i < dataRows.length; i++) {
    if (!selected.has(i)) continue;
    const proofPath = await buildProofPathDuplicateLast(leafHashes, i);
    const entry = {
      leaf_id: encodeLeafId(i),
      profile: NATIVE_PROFILE,
      value: dataRows[i],
      leaf_hash: leafHashes[i],
      proof_path: proofPath,
    };
    if (isSealed) {
      // The PER-LEAF salt for THIS revealed row — base64 (std). Revealing
      // per-leaf salts of revealed rows leaks nothing about the master or
      // any redacted row (HKDF-Expand is a PRF; csv-row-v1.md §5b.1).
      entry.salt_b64 = bytesToBase64(perLeafSalts[i]);
    }
    // STANDARD: NO salt_b64 — native standard is UNSALTED (0029 §5).
    revealed.push(entry);
  }

  // ── e. redacted-copy bytes ───────────────────────────────────────────
  // Rendering is per-strategy (0030 pt 4 / 0031), and presentation-only:
  // it feeds presentation.view_sha256 ONLY, never an on-chain hash.
  //   - SINGLE-MODE (csv/text): one renderRedactedCopy + fixed marker /
  //     structure_disclosure (line-oriented: header preserved, revealed
  //     leaves as their canonical value, redacted leaves as the marker in
  //     position, "\n"-joined, no trailing newline). renderMode IGNORED.
  //   - MULTI-MODE (json-keypath-v1): the user picks drop (DEFAULT) or
  //     mask; an unknown/absent renderMode falls back to defaultMode.
  let _renderFn, _redactionMarker, _structureDisclosure;
  if (strategy.modes) {
    const modeKey = (renderMode && strategy.modes[renderMode]) ? renderMode : strategy.defaultMode;
    const m = strategy.modes[modeKey];
    _renderFn = m.render; _redactionMarker = m.redactionMarker; _structureDisclosure = m.structureDisclosure;
  } else {
    _renderFn = strategy.renderRedactedCopy; _redactionMarker = strategy.redactionMarker; _structureDisclosure = strategy.structureDisclosure;
  }
  const redactedCopyBytes = _renderFn({
    headerRow,
    dataRows,
    selected,
    canonicalKeys,
    columnsCells,
    pointers,
    nodeValues,
    paths,
    spans,
  });
  const viewSha256 = await sha256Hex(redactedCopyBytes);

  // The unit a disclosure reveals/withholds, for the claims wording. Defaults
  // to "row"; csv-column-v1 sets "column" (matching the frozen CC1 fixture).
  const _claimsNoun = strategy.claimsNoun || "row";

  // ── disclosure block ──────────────────────────────────────────────────
  const id =
    disclosureId ||
    `redact-${revealed.length}of${dataRows.length}`;
  const disclosureBlock = {
    version: DISCLOSURE_VERSION,
    disclosure_id: id,
    linked_anchor: {
      root: committedRoot,
      txid,
      subject_profile: NATIVE_PROFILE,
      bundle_id: bundleId,
    },
    revealed,
    presentation: {
      format: strategy.format,
      view_sha256: viewSha256,
      redaction_marker: _redactionMarker,
      structure_disclosure: _structureDisclosure,
    },
    claims: {
      proves: [
        {
          code: "leaf_set_membership",
          text: `Revealed ${_claimsNoun}s were members of the original anchored leaf-set.`,
        },
        {
          code: "leaf_value_match",
          text: `Each revealed ${_claimsNoun}'s value matches the leaf the anchorer committed to.`,
        },
        {
          code: "presentation_integrity",
          text: "The included redacted view's bytes match presentation.view_sha256.",
        },
      ],
      does_not_prove: [
        {
          code: "incomplete_by_design",
          text: `This disclosure is incomplete by design; redacted ${_claimsNoun}s are withheld.`,
        },
        {
          code: "redacted_view_not_original",
          text: "The redacted view is not the original document.",
        },
        {
          code: "satsignal_does_not_certify",
          text: "Satsignal does not certify completeness or legal effect.",
        },
      ],
    },
  };

  // ── THE MASTER-SALT-STRIP GUARD (0029 pt 8 / csv-row-v1.md §5b.1) ─────
  // Defense in depth: the construction above never copies the master salt
  // anywhere, but a sealed source is security-critical, so we ASSERT it.
  // Serialize the entire returned surface (disclosure block + redacted
  // copy) and verify the master salt — in EVERY encoding (raw bytes, std
  // base64, base64url, hex lower/upper) — and every REDACTED row's
  // per-leaf salt are ABSENT. Any hit is a P0 leak and aborts the build.
  if (isSealed) {
    _assertMasterSaltStripped({
      masterSaltBytes,
      perLeafSalts,
      selected,
      disclosureBlock,
      redactedCopyBytes,
    });
  }

  return {
    disclosureBlock,
    redactedCopyBytes,
    dataRows,
    leafHashes,
    rootHex: committedRoot,
  };
}

/**
 * Encodings of a byte buffer that a leak could take. Scanned against the
 * serialized output to assert the master salt / redacted-row salts never
 * escape (0029 pt 8 / csv-row-v1.md §5b.1).
 * @param {Uint8Array} bytes
 * @returns {string[]} distinct non-empty encodings to scan for.
 */
function _leakEncodings(bytes) {
  const std = bytesToBase64(bytes);
  const url = std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const hexLower = bytesToHex(bytes);
  // Latin-1 view of the raw bytes — matches how the bytes would appear if
  // someone string-embedded them directly (parity with the redacted-copy
  // text + the JSON string scan).
  let rawStr = "";
  for (let i = 0; i < bytes.length; i++) rawStr += String.fromCharCode(bytes[i]);
  const out = [std, url, hexLower, hexLower.toUpperCase(), rawStr];
  return [...new Set(out)].filter((s) => s.length > 0);
}

/**
 * Hard P0 assertion that the SEALED disclosure output strips the master
 * salt and every redacted row's per-leaf salt. Throws RedactBindingError
 * on any hit (treated as a build-aborting leak, never a silent emit).
 */
function _assertMasterSaltStripped({
  masterSaltBytes,
  perLeafSalts,
  selected,
  disclosureBlock,
  redactedCopyBytes,
}) {
  // The serialized output surface: the disclosure block JSON + the
  // redacted-copy bytes as Latin-1 text. (The carrier canonical.json is
  // carried verbatim by the glue and provably contains no master salt —
  // it is the public anchor doc — so it is not part of this scan; the
  // glue's separate guard asserts the SOURCE manifest.json is not shipped.)
  const blockJson = JSON.stringify(disclosureBlock);
  let copyStr = "";
  for (let i = 0; i < redactedCopyBytes.length; i++) {
    copyStr += String.fromCharCode(redactedCopyBytes[i]);
  }
  const haystack = blockJson + " " + copyStr;

  // (1) the master salt — every encoding.
  for (const enc of _leakEncodings(masterSaltBytes)) {
    if (haystack.includes(enc)) {
      throw new RedactBindingError(
        "MASTER-SALT-STRIP VIOLATION: the master salt appears in the " +
          "disclosure output. Aborting (0029 pt 8 / csv-row-v1.md §5b.1).",
        { leak: "master_salt" }
      );
    }
  }
  // (2) every REDACTED row's per-leaf salt — only revealed rows may carry
  // a per-leaf salt. A redacted row's salt in the output would let a
  // recipient recompute that row's HMAC leaf.
  for (let j = 0; j < perLeafSalts.length; j++) {
    if (selected.has(j)) continue; // revealed rows legitimately carry it
    for (const enc of _leakEncodings(perLeafSalts[j])) {
      if (haystack.includes(enc)) {
        throw new RedactBindingError(
          `MASTER-SALT-STRIP VIOLATION: redacted row ${j} ` +
            `(${encodeLeafId(j)}) per-leaf salt appears in the output. ` +
            "Aborting (0029 pt 8 / csv-row-v1.md §5b.1).",
          { leak: "redacted_row_salt", index: j }
        );
      }
    }
  }
}
