"""
tests/test_snapshot_store.py — P2.1 page-snapshot object store acceptance suite.

Runs with zero cloud dependency: S3 is mocked at the HTTP layer with
``aioresponses`` (the same mock the rest of the suite uses), backed by an
in-memory fake bucket. Covers: dedup (one upload, ref reused), the legal
sanitization gate (no raw creds/PII in the stored object), read-back, the
unconfigured no-op, the TTL/staleness marker, and a SigV4 cross-check against
botocore when it is importable.
"""

from __future__ import annotations

import re
from datetime import timedelta
from urllib.parse import unquote, urlparse

import pytest
from aioresponses import CallbackResult, aioresponses
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import config
from db.models import Base
from shared_corpus import PageSnapshot
from snapshot_store import (
    S3ObjectStore,
    content_hash,
    is_stale,
    read_snapshot,
    stale_snapshots,
    store_snapshot,
)
from sanitizer import sanitize_page
from snapshot_store.store import SNAPSHOT_TTL, _now

_ENDPOINT = "https://acct.example.com"
_BUCKET = "snapshots-bucket"
_URL_PATTERN = re.compile(r"^https://acct\.example\.com/.*")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def Session(tmp_path):
    eng = create_engine(
        f"sqlite:///{(tmp_path / 'snap.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    yield sessionmaker(bind=eng, expire_on_commit=False)
    eng.dispose()


@pytest.fixture
def s3_configured(monkeypatch):
    monkeypatch.setattr(config, "PRIVATE_MODE", False)
    monkeypatch.setattr(config, "S3_ENDPOINT_URL", _ENDPOINT, raising=False)
    monkeypatch.setattr(config, "S3_BUCKET", _BUCKET, raising=False)
    monkeypatch.setattr(config, "S3_ACCESS_KEY_ID", "AKIAEXAMPLE", raising=False)
    monkeypatch.setattr(config, "S3_SECRET_ACCESS_KEY", "secretkey", raising=False)
    monkeypatch.setattr(config, "S3_REGION", "auto", raising=False)


@pytest.fixture
def s3_unconfigured(monkeypatch):
    for name in (
        "S3_ENDPOINT_URL",
        "S3_BUCKET",
        "S3_ACCESS_KEY_ID",
        "S3_SECRET_ACCESS_KEY",
    ):
        monkeypatch.setattr(config, name, None, raising=False)


class FakeBucket:
    """In-memory S3 bucket wired into aioresponses callbacks."""

    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.put_count = 0

    @staticmethod
    def _key(url) -> str:
        # path is /{bucket}/{key…}; strip the leading /{bucket}/.
        path = urlparse(str(url)).path.lstrip("/")
        _bucket, _, key = path.partition("/")
        return unquote(key)

    def head(self, url, **_kw):
        return CallbackResult(status=200 if self._key(url) in self.objects else 404)

    def put(self, url, **kw):
        data = kw.get("data")
        if hasattr(data, "read"):
            data = data.read()
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.objects[self._key(url)] = bytes(data or b"")
        self.put_count += 1
        return CallbackResult(status=200)

    def get(self, url, **_kw):
        key = self._key(url)
        if key in self.objects:
            return CallbackResult(status=200, body=self.objects[key])
        return CallbackResult(status=404)

    def mount(self, mock: aioresponses) -> None:
        mock.head(_URL_PATTERN, callback=self.head, repeat=True)
        mock.put(_URL_PATTERN, callback=self.put, repeat=True)
        mock.get(_URL_PATTERN, callback=self.get, repeat=True)


# ---------------------------------------------------------------------------
# Sanitization gate (pure, no network)
# ---------------------------------------------------------------------------

def test_sanitize_page_strips_credentials_and_pii():
    raw = (
        "Leak dump follows:\n"
        "victim@example.com:SuperSecret123\n"
        "URL: https://site.example/login\n"
        "USER: jdoe\n"
        "PASS: Hunter2Pass\n"
        "Contact analyst@corp.com or call +1 (555) 123 4567 for details.\n"
    )
    out = sanitize_page(raw)
    assert out is not None
    assert "SuperSecret123" not in out          # combo-line password gone
    assert "Hunter2Pass" not in out             # stealer-log password gone
    assert "victim@example.com" not in out      # combo-line email gone
    assert "analyst@corp.com" not in out        # standalone email redacted
    assert "555" not in out                     # phone redacted
    assert "CREDENTIAL_PRESENT" in out


def test_sanitize_page_drops_empty():
    assert sanitize_page("") is None
    assert sanitize_page(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Store / dedup / read-back
# ---------------------------------------------------------------------------

async def test_store_snapshot_uploads_and_records_ref(Session, s3_configured):
    bucket = FakeBucket()
    with aioresponses() as m:
        bucket.mount(m)
        with Session() as s, s.begin():
            row = await store_snapshot(s, "http://a.onion/leak", "hello world content")
            assert row is not None
            ref = row.storage_ref
            digest = row.content_hash
            # Provenance stamp (P2.2): source onion, capture timestamp, version.
            prov = row.provenance
            assert prov is not None
            assert prov["source"] == "a.onion"
            assert "captured_at" in prov and "T" in prov["captured_at"]
            assert prov["scraper_version"]

    # Object landed in the bucket under a content-addressed key + a DB ref row.
    assert bucket.put_count == 1
    assert ref in bucket.objects
    assert digest == content_hash(sanitize_page("hello world content").encode("utf-8"))
    with Session() as s:
        assert s.query(PageSnapshot).count() == 1


async def test_private_mode_writes_nothing_even_when_s3_configured(
    Session, s3_configured, monkeypatch
):
    """2.4: a private-mode install reads/writes nothing central, independent of
    whether S3 is configured."""
    import config

    monkeypatch.setattr(config, "PRIVATE_MODE", True, raising=False)
    bucket = FakeBucket()
    with aioresponses() as m:
        bucket.mount(m)
        with Session() as s, s.begin():
            row = await store_snapshot(s, "http://a.onion/x", "content that would upload")
        got = await read_snapshot("snapshots/ab/deadbeef")

    assert row is None            # wrote nothing
    assert got is None            # read nothing
    assert bucket.put_count == 0  # no upload attempt
    with Session() as s:
        assert s.query(PageSnapshot).count() == 0


async def test_store_snapshot_dedups_identical_content(Session, s3_configured):
    bucket = FakeBucket()
    content = "identical page body that repeats across investigations"
    with aioresponses() as m:
        bucket.mount(m)
        with Session() as s, s.begin():
            r1 = await store_snapshot(s, "http://a.onion/1", content)
        with Session() as s, s.begin():
            r2 = await store_snapshot(s, "http://b.onion/2-mirror", content)

    # Re-storing identical content makes no second upload and reuses the ref.
    assert bucket.put_count == 1
    assert r1.storage_ref == r2.storage_ref
    assert r1.content_hash == r2.content_hash
    with Session() as s:
        assert s.query(PageSnapshot).count() == 1


async def test_read_snapshot_returns_stored_sanitized_bytes(Session, s3_configured):
    bucket = FakeBucket()
    content = "readable page body for round-trip"
    with aioresponses() as m:
        bucket.mount(m)
        with Session() as s, s.begin():
            row = await store_snapshot(s, "http://a.onion/x", content)
        got = await read_snapshot(row.storage_ref)

    assert got == sanitize_page(content).encode("utf-8")


async def test_stored_object_contains_no_credentials_or_pii(Session, s3_configured):
    """Legal gate: creds/PII are sanitized before a byte reaches storage."""
    bucket = FakeBucket()
    raw = (
        "victim@example.com:SuperSecret123\n"
        "URL: https://site.example/login\n"
        "USER: jdoe\n"
        "PASS: Hunter2Pass\n"
        "reach analyst@corp.com / +1 (555) 123 4567\n"
    )
    with aioresponses() as m:
        bucket.mount(m)
        with Session() as s, s.begin():
            row = await store_snapshot(s, "http://a.onion/dump", raw)
        stored = await read_snapshot(row.storage_ref)

    blob = stored.decode("utf-8")
    assert "SuperSecret123" not in blob
    assert "Hunter2Pass" not in blob
    assert "victim@example.com" not in blob
    assert "analyst@corp.com" not in blob
    assert "555" not in blob


# ---------------------------------------------------------------------------
# Unconfigured = graceful no-op
# ---------------------------------------------------------------------------

async def test_unconfigured_store_is_noop(Session, s3_unconfigured):
    assert S3ObjectStore.from_config() is None
    with Session() as s, s.begin():
        row = await store_snapshot(s, "http://a.onion/x", "some content")
    assert row is None
    with Session() as s:
        assert s.query(PageSnapshot).count() == 0  # nothing written
    assert await read_snapshot("snapshots/ab/deadbeef") is None  # never raises


# ---------------------------------------------------------------------------
# TTL / staleness marker
# ---------------------------------------------------------------------------

def test_is_stale_and_stale_snapshots_query(Session):
    now = _now()
    with Session() as s, s.begin():
        fresh = PageSnapshot(
            content_hash="f" * 64, url="http://a.onion/fresh",
            captured_at=now, first_seen=now, last_seen=now,
        )
        old = PageSnapshot(
            content_hash="0" * 64, url="http://a.onion/old",
            captured_at=now - SNAPSHOT_TTL - timedelta(days=1),
            first_seen=now, last_seen=now,
        )
        s.add_all([fresh, old])

    with Session() as s:
        rows = {r.url: r for r in s.query(PageSnapshot).all()}
        assert is_stale(rows["http://a.onion/old"], now=now) is True
        assert is_stale(rows["http://a.onion/fresh"], now=now) is False

        stale = stale_snapshots(s, now=now)
        assert [r.url for r in stale] == ["http://a.onion/old"]


# ---------------------------------------------------------------------------
# SigV4 correctness (cross-check against botocore when available)
# ---------------------------------------------------------------------------

def test_sigv4_matches_botocore_reference(s3_configured):
    """Independent oracle: our hand-rolled SigV4 must equal botocore's S3 signer.

    Uses S3SigV4Auth (S3 does NOT normalize the request path, unlike the generic
    SigV4Auth) with payload signing forced (our signer signs the real payload
    hash, not UNSIGNED-PAYLOAD). Botocore picks the timestamp; we mirror it into
    our signer so both sign the identical instant.
    """
    pytest.importorskip("botocore")
    import datetime as _dt

    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    store = S3ObjectStore.from_config()
    assert store is not None
    key = "snapshots/ab/abcdef"
    body = b"payload-bytes"

    req = AWSRequest(method="PUT", url=store.object_url(key), data=body)
    req.context["payload_signing_enabled"] = True
    S3SigV4Auth(Credentials("AKIAEXAMPLE", "secretkey"), "s3", "auto").add_auth(req)

    amz_date = req.headers["X-Amz-Date"]
    now = _dt.datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(
        tzinfo=_dt.timezone.utc
    )
    ours = store._signed_headers("PUT", key, body, now=now)

    assert ours["x-amz-content-sha256"] == req.headers["X-Amz-Content-SHA256"]
    assert ours["Authorization"] == req.headers["Authorization"]
