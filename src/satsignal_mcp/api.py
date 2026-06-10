"""Thin async httpx wrapper around the Satsignal customer API.

Only the two endpoints the MCP server touches:

- POST /api/v1/anchors          Bearer-authed. Body shape per
                                customer/routes.py:_post_api_anchors.
- GET  /lookup_hash?sha=<hex>   Public, rate-limited, ACAO:*.

Vocabulary (decision 0046): requests SEND the canonical `folder_slug`
key; responses are READ canonical-first (`proof_id`, `proof_url`,
`folder_slug`) with a legacy fallback (`bundle_id`, `receipt_url`,
`matter_slug`) retained for older / self-hosted Satsignal servers that
still emit the pre-rename keys.

Responses are returned as parsed dicts. HTTP-level failures raise
ApiError with an integrator-readable summary; the original JSON body
(if any) is attached for callers that want to render the server's own
error code + message.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from . import __version__


# app.satsignal.cloud is the customer API host (POST /api/v1/anchors,
# bundle download, dashboard). proof.satsignal.cloud is the public
# verifier surface and serves /lookup_hash mirror-mode, but customer
# routes 404 there because the notary's host dispatcher only invokes
# them when Host matches `_APP_HOSTS`. v0.1.0 incorrectly defaulted to
# proof.*, which silently broke every anchor_* tool out of the box —
# `verify_bundle` masked the bug because lookup_hash works on both.
DEFAULT_API_BASE = "https://app.satsignal.cloud"
# Derived from package metadata so the UA can't lag the release again
# (it sat frozen at 0.2.1 through 0.5.5).
_USER_AGENT = f"satsignal-mcp/{__version__}"


class ApiError(Exception):
    """Non-2xx response from the Satsignal API."""

    def __init__(self, status: int, code: str, message: str,
                 *, body: Optional[dict] = None):
        super().__init__(f"satsignal API {status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.body = body or {}


@dataclass
class AnchorResult:
    """Subset of the /api/v1/anchors response we surface to MCP callers.

    Field names follow the canonical vocabulary (decision 0046):
    proof_id / folder_slug / proof_url. The parser accepts the legacy
    response keys (bundle_id / matter_slug / receipt_url) as fallbacks
    for older / self-hosted servers.
    """

    proof_id: str
    txid: Optional[str]
    mode: str
    folder_slug: str
    proof_url: str
    bundle_url: Optional[str]
    duplicate: bool
    raw: dict  # full server response, in case the LLM wants it


def _parse_api_error(status: int, body_text: str) -> ApiError:
    """Map a non-2xx body to an ApiError. Server errors follow
    {"error": {"code", "message"}} per customer/routes.py:_api_error."""
    try:
        body = json.loads(body_text)
    except (ValueError, json.JSONDecodeError):
        return ApiError(status, "non_json_response",
                        body_text[:200] or f"HTTP {status}")
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        return ApiError(
            status,
            str(err.get("code") or "unknown_error"),
            str(err.get("message") or ""),
            body=body,
        )
    # /lookup_hash uses a flatter {"error": "..."} shape.
    if isinstance(body, dict) and isinstance(body.get("error"), str):
        return ApiError(status, body["error"], "", body=body)
    return ApiError(status, "unknown_error", str(body)[:200], body=body)


class SatsignalApi:
    """Async client. Constructed once per server lifetime.

    api_key is required for /api/v1/anchors; /lookup_hash works without
    auth. The key is sent as Bearer and never logged.
    """

    def __init__(self, *, api_base: str, api_key: Optional[str],
                 timeout: float = 30.0):
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "SatsignalApi":
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.aclose()

    # ---- POST /api/v1/anchors -----------------------------------------

    async def anchor_standard(
        self,
        *,
        folder_slug: str,
        sha256_hex: str,
        file_size: Optional[int] = None,
        label: Optional[str] = None,
        filename: Optional[str] = None,
        force_new: bool = False,
    ) -> AnchorResult:
        if not self.api_key:
            raise ApiError(
                401, "missing_api_key",
                "SATSIGNAL_API_KEY env var is required for anchoring; "
                "set it in the MCP client config.",
            )
        body: dict[str, Any] = {
            # Canonical wire key (decision 0046). The server still
            # accepts the legacy `matter_slug` as a silent alias, but
            # tooling must send canonical.
            "folder_slug": folder_slug,
            "sha256_hex": sha256_hex.lower().strip(),
        }
        if file_size is not None:
            body["file_size"] = int(file_size)
        if label:
            body["label"] = label
        if filename:
            body["filename"] = filename
        if force_new:
            body["force_new"] = True
        resp = await self._client.post(
            f"{self.api_base}/api/v1/anchors",
            json=body,
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        if resp.status_code >= 400:
            raise _parse_api_error(resp.status_code, resp.text)
        data = resp.json()
        # Canonical keys first; legacy keys kept as a read fallback for
        # older / self-hosted servers that predate the rename.
        return AnchorResult(
            proof_id=str(data.get("proof_id") or data.get("bundle_id") or ""),
            txid=data.get("txid"),
            mode=str(data.get("mode") or "standard"),
            folder_slug=str(data.get("folder_slug")
                            or data.get("matter_slug") or folder_slug),
            proof_url=str(data.get("proof_url")
                          or data.get("receipt_url") or ""),
            bundle_url=data.get("bundle_url"),
            duplicate=bool(data.get("duplicate", False)),
            raw=data,
        )

    # ---- GET /lookup_hash?sha=<hex> -----------------------------------

    async def lookup_hash(self, sha256_hex: str) -> dict:
        sha = sha256_hex.lower().strip()
        resp = await self._client.get(
            f"{self.api_base}/lookup_hash",
            params={"sha": sha},
        )
        if resp.status_code >= 400:
            raise _parse_api_error(resp.status_code, resp.text)
        return resp.json()
