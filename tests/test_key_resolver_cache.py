from __future__ import annotations

import threading
from importlib.resources import files

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from fr_2ddoc_parser.crypto import key_resolver as kr


def _tsl_bytes() -> bytes:
    return files("fr_2ddoc_parser.crypto.keys").joinpath("tsl_signed.xml").read_bytes()


def test_from_tsl_fetches_leaves_by_default(monkeypatch):
    called: list[str] = []

    def fake_fetch(url, timeout=10):
        called.append(url)
        return None

    monkeypatch.setattr(kr, "_fetch_bytes", fake_fetch)
    resolver = kr.KeyResolver.from_tsl(_tsl_bytes())
    assert called
    assert resolver._per_ca_leaf == {}


def test_from_tsl_can_skip_fetching(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("network access during from_tsl")

    monkeypatch.setattr(kr, "_fetch_bytes", fail)
    resolver = kr.KeyResolver.from_tsl(_tsl_bytes(), fetch_leaves=False)
    assert resolver._per_ca_leaf == {}


def test_refresh_writes_cache_and_load_cache_reads_it(tmp_path, monkeypatch):
    resolver = kr.KeyResolver.from_tsl(_tsl_bytes(), fetch_leaves=False)
    ca_id = next(iter(resolver._tsp_uris))
    cert = resolver._per_ca[ca_id][0]
    pem = cert.public_bytes(Encoding.PEM)

    monkeypatch.setattr(kr, "_fetch_bytes", lambda *args, **kwargs: pem)
    resolver.refresh_leaves(ca_id, cache_dir=tmp_path)

    cache_file = tmp_path / f"{ca_id}.pem"
    assert cache_file.is_file()

    def fail(*args, **kwargs):
        raise AssertionError("network access while loading cache")

    monkeypatch.setattr(kr, "_fetch_bytes", fail)
    cached = kr.KeyResolver.from_tsl(
        _tsl_bytes(), fetch_leaves=False, cache_dir=tmp_path
    )
    assert ca_id in cached._per_ca_leaf
    assert cached._per_ca_leaf[ca_id]


def test_load_key_resolver_is_lazy_without_cache(monkeypatch):
    monkeypatch.delenv(kr.CACHE_DIR_ENV, raising=False)
    resolver = kr.load_key_resolver()
    ca_id = next(iter(resolver._tsp_uris))
    called: list[str] = []

    def fake_fetch(url, timeout=10):
        called.append(url)
        return None

    monkeypatch.setattr(kr, "_fetch_bytes", fake_fetch)

    try:
        resolver.resolve(ca_id, "XXXX")
    except KeyError:
        pass

    assert called == resolver._tsp_uris[ca_id]


def test_load_key_resolver_is_offline_when_cache_configured(tmp_path, monkeypatch):
    monkeypatch.setenv(kr.CACHE_DIR_ENV, str(tmp_path))
    resolver = kr.load_key_resolver()
    assert resolver._lazy_leaves is False


def test_partial_refresh_preserves_cached_certs(monkeypatch):
    resolver = kr.KeyResolver.from_tsl(_tsl_bytes(), fetch_leaves=False)
    ca_id = next(iter(resolver._tsp_uris))
    uri = resolver._tsp_uris[ca_id][0]
    old_cert = resolver._per_ca[ca_id][0]
    other_ca = next(ca for ca in resolver._per_ca if ca != ca_id)
    new_cert = resolver._per_ca[other_ca][0]
    resolver._per_ca_leaf[ca_id] = [old_cert]

    html = b'<html><a href="a.cer">a</a><a href="b.cer">b</a></html>'

    def fake_fetch(url, timeout=10):
        if url == uri:
            return html
        if url.endswith("a.cer"):
            return new_cert.public_bytes(Encoding.PEM)
        return None

    monkeypatch.setattr(kr, "_fetch_bytes", fake_fetch)
    resolver.refresh_leaves(ca_id)

    ders = {c.public_bytes(Encoding.DER) for c in resolver._per_ca_leaf[ca_id]}
    assert old_cert.public_bytes(Encoding.DER) in ders
    assert new_cert.public_bytes(Encoding.DER) in ders


def test_unparseable_link_preserves_cached_certs(monkeypatch):
    resolver = kr.KeyResolver.from_tsl(_tsl_bytes(), fetch_leaves=False)
    ca_id = next(iter(resolver._tsp_uris))
    uri = resolver._tsp_uris[ca_id][0]
    old_cert = resolver._per_ca[ca_id][0]
    other_ca = next(ca for ca in resolver._per_ca if ca != ca_id)
    new_cert = resolver._per_ca[other_ca][0]
    resolver._per_ca_leaf[ca_id] = [old_cert]

    html = b'<html><a href="a.cer">a</a><a href="b.cer">b</a></html>'

    def fake_fetch(url, timeout=10):
        if url == uri:
            return html
        if url.endswith("a.cer"):
            return new_cert.public_bytes(Encoding.PEM)
        return b"not a certificate"

    monkeypatch.setattr(kr, "_fetch_bytes", fake_fetch)
    resolver.refresh_leaves(ca_id)

    ders = {c.public_bytes(Encoding.DER) for c in resolver._per_ca_leaf[ca_id]}
    assert old_cert.public_bytes(Encoding.DER) in ders
    assert new_cert.public_bytes(Encoding.DER) in ders


def test_refresh_keys_raises_when_no_leaves(tmp_path, monkeypatch):
    monkeypatch.setattr(kr, "_fetch_bytes", lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError):
        kr.refresh_keys(tmp_path)


def test_failed_lazy_fetch_is_retried(monkeypatch):
    resolver = kr.KeyResolver.from_tsl(
        _tsl_bytes(), fetch_leaves=False, lazy_leaves=True
    )
    ca_id = next(iter(resolver._tsp_uris))
    called: list[str] = []

    def fake_fetch(url, timeout=10):
        called.append(url)
        return None

    monkeypatch.setattr(kr, "_fetch_bytes", fake_fetch)

    for _ in range(2):
        try:
            resolver.resolve(ca_id, "XXXX")
        except KeyError:
            pass

    assert len(called) == 2 * len(resolver._tsp_uris[ca_id])
    assert ca_id not in resolver._leaves_loaded


def test_slow_download_does_not_block_other_ca(monkeypatch):
    resolver = kr.KeyResolver.from_tsl(
        _tsl_bytes(), fetch_leaves=False, lazy_leaves=True
    )
    slow_ca, fast_ca = list(resolver._tsp_uris)[:2]
    fast_cert = resolver._per_ca[fast_ca][0]
    resolver._per_ca_leaf[fast_ca] = [fast_cert]
    resolver._leaves_loaded.add(fast_ca)

    started = threading.Event()
    release = threading.Event()
    slow_uri = resolver._tsp_uris[slow_ca][0]

    def fake_fetch(url, timeout=10):
        if url == slow_uri:
            started.set()
            release.wait(timeout=5)
        return None

    monkeypatch.setattr(kr, "_fetch_bytes", fake_fetch)

    def slow_resolve():
        try:
            resolver.resolve(slow_ca, "XXXX")
        except KeyError:
            pass

    slow_thread = threading.Thread(target=slow_resolve)
    slow_thread.start()
    try:
        assert started.wait(timeout=5)

        fast_done = threading.Event()

        def fast_resolve():
            resolver.resolve(fast_ca, "XXXX")
            fast_done.set()

        fast_thread = threading.Thread(target=fast_resolve)
        fast_thread.start()
        assert fast_done.wait(timeout=1)
        fast_thread.join(timeout=5)
    finally:
        release.set()
        slow_thread.join(timeout=5)


def test_load_cache_is_idempotent(tmp_path):
    resolver = kr.KeyResolver.from_tsl(_tsl_bytes(), fetch_leaves=False)
    ca_id = next(iter(resolver._tsp_uris))
    cert = resolver._per_ca[ca_id][0]
    (tmp_path / f"{ca_id}.pem").write_bytes(cert.public_bytes(Encoding.PEM))

    resolver.load_cache(tmp_path)
    resolver.load_cache(tmp_path)

    assert resolver.leaf_count(ca_id) == 1


def test_main_fails_when_no_leaves(tmp_path, monkeypatch):
    monkeypatch.setattr(kr, "_fetch_bytes", lambda *args, **kwargs: None)
    assert kr.main(["--cache-dir", str(tmp_path)]) == 1


def test_lazy_leaves_only_fetch_requested_ca(monkeypatch):
    resolver = kr.KeyResolver.from_tsl(
        _tsl_bytes(), fetch_leaves=False, lazy_leaves=True
    )
    ca_id = next(iter(resolver._tsp_uris))
    called: list[str] = []

    def fake_fetch(url, timeout=10):
        called.append(url)
        return None

    monkeypatch.setattr(kr, "_fetch_bytes", fake_fetch)

    try:
        resolver.resolve(ca_id, "XXXX")
    except KeyError:
        pass

    assert called == resolver._tsp_uris[ca_id]
