// mcp_disclosure_cli.mjs — thin JSON stdio entrypoint for satsignal-mcp's
// disclosable-* tools (anchor_disclosable / create_disclosure / verify_disclosure).
//
// This is the ONE hand-written file in this vendor dir; every sibling is a
// VERBATIM vendored snapshot of the JS source of truth (see VENDOR.md). It is
// NOT overwritten by scripts/sync_vendored_builder.py.
//
// Contract: read ONE JSON request object from stdin, write ONE JSON response
// object to stdout, exit 0 on ok / 1 on a handled failure.
//
//   request  : {"op":"anchor"|"create"|"verify"|"list", ...params}
//   response : {"ok":true, ...result} | {"ok":false, error_code, message,
//                error_class?, fail_code?}
//
// SECURITY INVARIANT: stdout carries JSON ONLY, and NEVER the master salt.
// anchorToMbnt returns masterSaltHex + body.salt_b64 (the bearer secret); both
// are stripped/redacted here before anything is written. The bearer API token
// is read from process.env.SATSIGNAL_API_KEY (set by node_bridge.py for the
// anchor op only) — never from argv.

import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";

import { anchorToMbnt, granularityForExt } from "./anchor-to-mbnt.mjs";
import {
  redactFromMbnt,
  listMbntLeaves,
  parseSourceMembers,
} from "./redact-from-mbnt.mjs";
import { readMbntMembers } from "./mbnt-read.mjs";
import { verifyDisclosureCore } from "./verify-disclosure.mjs";
import { RedactBindingError } from "./redact-core.mjs";

const _td = new TextDecoder();

function _sha256hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function ok(obj) {
  return { ok: true, ...obj };
}

function fail(error_code, message, extra = {}) {
  return { ok: false, error_code, message, ...extra };
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf-8");
}

function _chunkMerkleScheme(canonicalJson) {
  const cm =
    canonicalJson &&
    canonicalJson.subject &&
    canonicalJson.subject.proofs &&
    canonicalJson.subject.proofs.chunk_merkle;
  return cm && typeof cm === "object" ? cm.scheme : undefined;
}

// ── anchor ────────────────────────────────────────────────────────────────
// Build a SEALED text-tree-v1/json-ast-v1 envelope and anchor it. The one-shot
// "also emit a disclosure" path is orchestrated by the Python handler as a
// SEPARATE create op against the returned source .mbnt, so this op stays atomic.
async function opAnchor(p) {
  const granularity = p.granularity || granularityForExt(p.file_path || "");
  if (granularity !== "tree" && granularity !== "ast") {
    return fail(
      "bad_granularity",
      `could not determine granularity for ${JSON.stringify(p.file_path)} — ` +
        `only .txt (tree) and .json (ast) auto-detect; pass granularity ` +
        `"tree" or "ast" explicitly.`
    );
  }
  const res = await anchorToMbnt(p.file_path, {
    apiKey: process.env.SATSIGNAL_API_KEY || undefined,
    base: p.base || undefined,
    folderSlug: p.folder_slug,
    createFolder: !!p.create_folder,
    granularity,
    storage: p.storage || "mirror",
    category: p.category,
    outDir: p.out_dir,
    dryRun: !!p.dry_run,
  });

  // STRIP SECRETS. Drop masterSaltHex entirely. The POST body carries salt_b64
  // (mirror mode) + the full proof_set; surface a salt-redacted body only for
  // dry_run previews, and drop it on a live anchor (not useful, salt-bearing).
  const { masterSaltHex: _drop, body, bundleId, ...safe } = res;
  void _drop;
  const out = { ...safe };
  if (bundleId !== undefined) out.proof_id = bundleId; // canonical vocab (0046)
  if (p.dry_run && body) {
    const safeBody = { ...body };
    if ("salt_b64" in safeBody) safeBody.salt_b64 = "[REDACTED]";
    out.body = safeBody;
  }
  return ok(out);
}

// ── create (redact) ─────────────────────────────────────────────────────────
// Local-only: redact from an already-anchored SOURCE .mbnt; no network, no key.
async function opCreate(p) {
  const res = await redactFromMbnt(p.original_path, p.source_mbnt_path, {
    reveal: p.reveal,
    revealNames: p.reveal_names,
    renderMode: p.render_mode,
    outDir: p.out_dir,
    selfVerify: true,
  });
  const block = res.disclosureBlock || {};
  const revealedCount = Array.isArray(block.revealed)
    ? block.revealed.length
    : undefined;
  return ok({
    redacted_copy_path: res.redactedCopyPath,
    disclosure_mbnt_path: res.disclosureMbntPath,
    root: res.rootHex,
    revealed_count: revealedCount,
    // self-verify {ok, fail_code}: a redaction whose result does not bind is a
    // build failure — the Python handler treats verify.ok===false as fatal.
    self_verify: res.verify,
  });
}

// ── list ────────────────────────────────────────────────────────────────────
// Enumerate the source .mbnt's leaves + copy-pastable selectors. Writes nothing.
async function opList(p) {
  const originalBytes = new Uint8Array(await readFile(p.original_path));
  const mbntBytes = new Uint8Array(await readFile(p.source_mbnt_path));
  const parsed = parseSourceMembers(readMbntMembers(mbntBytes));
  const rows = await listMbntLeaves(originalBytes, parsed);
  return ok({
    scheme: _chunkMerkleScheme(parsed.canonicalJson),
    leaf_count: rows.length,
    leaves: rows,
  });
}

// ── verify ───────────────────────────────────────────────────────────────────
// Cryptographic BIND of a disclosure .mbnt: the revealed leaves walk to
// linked_anchor.root, the carrier matches the disclosure's claimed canonical
// hash, profile/algo bind, and (if a view is supplied) the redacted view's
// sha256 matches. verified===false is a SUCCESS (ok:true) result, mirroring
// verify_file_against_bundle; only an unreadable / malformed bundle is ok:false.
//
// NOTE on the chain layer: linked_anchor.{txid,root} are surfaced for
// independent on-chain confirmation via a BSV explorer. lookup_hash CANNOT
// confirm these — sealed/manifest anchors expose no naked file sha to index
// (the same reason chain_confirm_bundle returns no_file_sha for them) — so this
// op does the cryptographic bind and reports the txid/root rather than a chain
// lookup that would always miss.
async function opVerify(p) {
  const mbntBytes = new Uint8Array(await readFile(p.disclosure_mbnt_path));
  const members = readMbntMembers(mbntBytes);

  const manifestBytes = members["manifest.json"];
  if (manifestBytes == null) {
    return fail("bad_disclosure", "disclosure .mbnt has no manifest.json");
  }
  let manifest;
  try {
    manifest = JSON.parse(_td.decode(manifestBytes));
  } catch (e) {
    return fail("bad_disclosure", `manifest.json is not valid JSON: ${e.message}`);
  }
  const disclosureBlock = manifest && manifest.disclosure;
  if (!disclosureBlock || typeof disclosureBlock !== "object") {
    return fail("bad_disclosure", "manifest.json has no disclosure block");
  }
  const carrierBytes = members["linked_anchor/canonical.json"];
  if (carrierBytes == null) {
    return fail(
      "bad_disclosure",
      "disclosure .mbnt has no linked_anchor/canonical.json carrier"
    );
  }

  // Full sha256 of the verbatim carrier — the verifier compares the on-chain
  // commit against the first onChainCommit.length hex chars, so a full hash is
  // a full-equality check (matches the redact self-verify recipe).
  const onChainCommit = _sha256hex(carrierBytes);

  let viewBytes;
  if (typeof p.view_path === "string" && p.view_path) {
    viewBytes = new Uint8Array(await readFile(p.view_path));
  }

  const result = await verifyDisclosureCore(disclosureBlock, {
    carrierBytes,
    onChainCommit,
    viewBytes,
  });

  const la = disclosureBlock.linked_anchor || {};
  return ok({
    verified: result.ok === true,
    fail_code: result.fail_code ?? null,
    scheme: la.subject_profile,
    root: la.root,
    linked_txid: la.txid,
    carrier_sha256: onChainCommit,
    revealed_count: Array.isArray(disclosureBlock.revealed)
      ? disclosureBlock.revealed.length
      : undefined,
    // True only when a comparison actually ran: verifyDisclosureCore compares
    // the view sha256 only when the block carries a `presentation` (with its
    // view_sha256 commitment). A view supplied against a presentation-less
    // block is never compared, so reporting view_checked:true would overclaim.
    view_checked: viewBytes != null && disclosureBlock.presentation != null,
  });
}

const _OPS = {
  anchor: opAnchor,
  create: opCreate,
  list: opList,
  verify: opVerify,
};

async function main() {
  let req;
  try {
    req = JSON.parse(await readStdin());
  } catch (e) {
    process.stdout.write(
      JSON.stringify(fail("bad_request", `could not parse JSON request: ${e.message}`))
    );
    process.exit(2);
  }

  const op = req && req.op;
  const handler = _OPS[op];
  if (!handler) {
    process.stdout.write(
      JSON.stringify(fail("unknown_op", `unknown op: ${JSON.stringify(op)}`))
    );
    process.exit(2);
  }

  let result;
  try {
    result = await handler(req);
  } catch (e) {
    if (e instanceof RedactBindingError) {
      result = fail("redact_binding_error", e.message, {
        error_class: "RedactBindingError",
        detail: e.detail ?? null,
      });
    } else {
      result = fail("node_op_error", (e && e.message) || String(e), {
        error_class: (e && e.constructor && e.constructor.name) || "Error",
      });
    }
  }

  process.stdout.write(JSON.stringify(result));
  process.exit(result.ok ? 0 : 1);
}

main();
