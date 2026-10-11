"""
snapshot_store/s3.py — a minimal, provider-agnostic S3 client.

Configured by endpoint + bucket + credentials, so Cloudflare R2 (production,
zero-egress), MinIO (dev/test/$0), or any S3-compatible store are the *same
code*. There is deliberately **no** boto3/aioboto3/minio dependency:

* requests go over the shared clearnet ``aiohttp`` session (``netpool``);
* authentication is AWS Signature V4, hand-rolled with stdlib ``hmac``/
  ``hashlib`` — ~40 lines, works offline, and mocks cleanly with
  ``aioresponses`` (no cloud in CI);
* timeouts/retries come from ``pacing`` (project rule CC-4 — nothing hardcoded).

Path-style addressing (``{endpoint}/{bucket}/{key}``) is used rather than
virtual-host style so an arbitrary endpoint (MinIO, a local gateway) works
without the bucket having to be a DNS label.

An unconfigured store (any of endpoint/bucket/key/secret missing) is represented
by ``S3ObjectStore.from_config()`` returning ``None`` — callers no-op.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import hashlib
import hmac
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote, urlparse

import aiohttp

import pacing

# ``normal`` baselines — scaled through pacing at the call site (see CC-4). R2 is
# our own infrastructure, not a third-party quota, so plain timeout/retry scaling
# applies (not scale_delay_floor).
_S3_TIMEOUT = 30.0
_S3_MAX_RETRIES = 2
_S3_RETRY_DELAYS = (0.5, 1.0)

_SERVICE = "s3"
_ALGORITHM = "AWS4-HMAC-SHA256"
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k_date = _sign(("AWS4" + secret).encode("utf-8"), datestamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    return _sign(k_service, "aws4_request")


@dataclass(frozen=True)
class S3Config:
    endpoint_url: str
    bucket: str
    access_key_id: str
    secret_access_key: str
    region: str = "auto"

    @classmethod
    def from_config(cls) -> Optional["S3Config"]:
        """Build from ``config`` module values, or ``None`` if not fully set.

        Read live (not import-time) so tests can monkeypatch ``config.S3_*`` and
        so a key added to the environment after import takes effect.
        """
        import config

        endpoint = (getattr(config, "S3_ENDPOINT_URL", None) or "").strip()
        bucket = (getattr(config, "S3_BUCKET", None) or "").strip()
        access = (getattr(config, "S3_ACCESS_KEY_ID", None) or "").strip()
        secret = (getattr(config, "S3_SECRET_ACCESS_KEY", None) or "").strip()
        region = (getattr(config, "S3_REGION", None) or "auto").strip() or "auto"

        if not (endpoint and bucket and access and secret):
            return None
        return cls(
            endpoint_url=endpoint.rstrip("/"),
            bucket=bucket,
            access_key_id=access,
            secret_access_key=secret,
            region=region,
        )


class S3ObjectStore:
    """Async put/get/head against an S3-compatible endpoint, SigV4-signed."""

    def __init__(self, cfg: S3Config):
        self._cfg = cfg
        self._host = urlparse(cfg.endpoint_url).netloc

    @classmethod
    def from_config(cls) -> Optional["S3ObjectStore"]:
        """Return a store, or ``None`` when object storage is not configured."""
        cfg = S3Config.from_config()
        return cls(cfg) if cfg is not None else None

    # -- addressing --------------------------------------------------------

    def _canonical_uri(self, key: str) -> str:
        # Path-style: /{bucket}/{key}. S3 UriEncode keeps slashes; Python's quote
        # already leaves unreserved chars (A-Za-z0-9-._~) and, with safe="/",
        # path separators unencoded — matching the canonical-URI rule.
        return "/" + quote(self._cfg.bucket, safe="") + "/" + quote(key, safe="/")

    def object_url(self, key: str) -> str:
        return f"{self._cfg.endpoint_url}{self._canonical_uri(key)}"

    # -- signing -----------------------------------------------------------

    def _signed_headers(
        self, method: str, key: str, payload: bytes, now: Optional[_dt.datetime] = None
    ) -> dict[str, str]:
        now = now or _dt.datetime.now(_dt.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        payload_hash = _sha256_hex(payload) if payload else _EMPTY_SHA256

        canonical_headers = (
            f"host:{self._host}\n"
            f"x-amz-content-sha256:{payload_hash}\n"
            f"x-amz-date:{amz_date}\n"
        )
        signed_headers = "host;x-amz-content-sha256;x-amz-date"

        canonical_request = "\n".join(
            [
                method,
                self._canonical_uri(key),
                "",  # canonical query string
                canonical_headers,
                signed_headers,
                payload_hash,
            ]
        )
        scope = f"{datestamp}/{self._cfg.region}/{_SERVICE}/aws4_request"
        string_to_sign = "\n".join(
            [
                _ALGORITHM,
                amz_date,
                scope,
                _sha256_hex(canonical_request.encode("utf-8")),
            ]
        )
        signing_key = _signing_key(
            self._cfg.secret_access_key, datestamp, self._cfg.region, _SERVICE
        )
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        authorization = (
            f"{_ALGORITHM} Credential={self._cfg.access_key_id}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        return {
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
            "Authorization": authorization,
        }

    # -- transport ---------------------------------------------------------

    async def _request(
        self,
        method: str,
        key: str,
        *,
        body: bytes = b"",
        extra_headers: Optional[dict[str, str]] = None,
    ) -> tuple[int, bytes]:
        from netpool import get_clearnet_session

        url = self.object_url(key)
        headers = self._signed_headers(method, key, body)
        if extra_headers:
            headers.update(extra_headers)

        timeout = aiohttp.ClientTimeout(total=pacing.scale_timeout(_S3_TIMEOUT))
        max_retries, delays = pacing.retry_plan(_S3_MAX_RETRIES, _S3_RETRY_DELAYS)

        attempt = 0
        while True:
            try:
                session = get_clearnet_session()
                async with session.request(
                    method,
                    url,
                    data=body if body else None,
                    headers=headers,
                    timeout=timeout,
                ) as resp:
                    content = await resp.read()
                    # Retry transient server errors; 4xx are terminal.
                    if resp.status >= 500 and attempt < max_retries:
                        raise aiohttp.ClientError(f"S3 {resp.status}")
                    return resp.status, content
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt >= max_retries:
                    raise
                if delays:
                    await asyncio.sleep(delays[min(attempt, len(delays) - 1)])
                attempt += 1

    # -- public operations -------------------------------------------------

    async def put_object(
        self, key: str, body: bytes, *, content_type: str = "text/plain; charset=utf-8"
    ) -> bool:
        """Upload *body* to *key*. Returns True on a 2xx response."""
        status, _ = await self._request(
            "PUT", key, body=body, extra_headers={"Content-Type": content_type}
        )
        return 200 <= status < 300

    async def get_object(self, key: str) -> Optional[bytes]:
        """Fetch the object at *key*, or ``None`` if it does not exist (404)."""
        status, content = await self._request("GET", key)
        if status == 404:
            return None
        if 200 <= status < 300:
            return content
        raise RuntimeError(f"S3 GET {key} returned {status}")

    async def object_exists(self, key: str) -> bool:
        """True if an object exists at *key* (HEAD 2xx); False on 404."""
        status, _ = await self._request("HEAD", key)
        if status == 404:
            return False
        if 200 <= status < 300:
            return True
        raise RuntimeError(f"S3 HEAD {key} returned {status}")
