#!/usr/bin/env python3
"""
Usage:
  fpkg_head_analyzer.py base.head.pkg upd.head.pkg --keys keys.rs
  fpkg_head_analyzer.py https://h/base.pkg https://h/upd.pkg --keys keys.rs
"""
import argparse
import hashlib
import os
import struct
import sys
import time
import urllib.error
import urllib.request
import zlib
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from fpkg_lowmem import XTS_SECTOR, Pfs, SliceImage, XtsImage, load_rsa_keys


# ------------------------------------------------------------------ sources
class NeedMoreData(Exception):
    """A read went past the end of a head-only file."""

    def __init__(self, needed, available):
        super().__init__(f"need bytes up to {needed}, only {available} available")
        self.needed, self.available = needed, available


def _slice_bounds(key, total):
    if not isinstance(key, slice):
        raise TypeError("only slice access is supported")
    start = key.start or 0
    stop = total if key.stop is None else key.stop
    return start, max(start, stop)


class FileSource:
    """Local file (possibly only the first N bytes of the real package)."""

    kind = "file"

    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self.avail = os.fstat(self.f.fileno()).st_size
        self.max_end = 0
        self.bytes_read = 0

    def __getitem__(self, key):
        start, stop = _slice_bounds(key, self.avail)
        if stop > self.avail:
            raise NeedMoreData(stop, self.avail)
        self.f.seek(start)
        data = self.f.read(stop - start)
        self.max_end = max(self.max_end, stop)
        self.bytes_read += len(data)
        return data

    def stats(self):
        return f"file has {self.avail / 2**20:.1f} MiB, highest offset used {self.max_end / 2**20:.2f} MiB"


class RangeSource:
    """HTTP(S) source using Range requests with an LRU block cache."""

    kind = "http"

    def __init__(self, url, block=1 << 20, cache_blocks=64):
        self.url, self.block = url, block
        self.cache = OrderedDict()
        self.max_cache = cache_blocks
        self.requests = 0
        self.fetched = 0
        self.max_end = 0
        self.size = self._probe_size()

    def _open(self, req):
        last = None
        for attempt in range(3):
            try:
                return urllib.request.urlopen(req, timeout=60)
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last = exc
                time.sleep(1 + attempt)
        raise OSError(f"request failed: {last}")

    def _probe_size(self):
        req = urllib.request.Request(self.url, headers={"Range": "bytes=0-0"})
        with self._open(req) as r:
            if r.status != 206:
                raise OSError("server ignored Range request (no partial download support)")
            cr = r.headers.get("Content-Range", "")
            r.read()
        if "/" not in cr or cr.rsplit("/", 1)[1] == "*":
            raise OSError("server did not report total size in Content-Range")
        return int(cr.rsplit("/", 1)[1])

    def _block(self, i):
        if i in self.cache:
            self.cache.move_to_end(i)
            return self.cache[i]
        a = i * self.block
        b = min(a + self.block, self.size) - 1
        req = urllib.request.Request(self.url, headers={"Range": f"bytes={a}-{b}"})
        with self._open(req) as r:
            if r.status != 206:
                raise OSError("server ignored Range request")
            data = r.read()
        if len(data) != b - a + 1:
            raise OSError(f"short range response at {a}")
        self.requests += 1
        self.fetched += len(data)
        self.max_end = max(self.max_end, b + 1)
        self.cache[i] = data
        if len(self.cache) > self.max_cache:
            self.cache.popitem(last=False)
        return data

    def __getitem__(self, key):
        start, stop = _slice_bounds(key, self.size)
        stop = min(stop, self.size)
        out = bytearray()
        pos = start
        while pos < stop:
            i, o = divmod(pos, self.block)
            chunk = self._block(i)[o:o + (stop - pos)]
            out += chunk
            pos += len(chunk)
        return bytes(out)

    def stats(self):
        return (f"fetched {self.fetched / 2**20:.2f} MiB in {self.requests} requests "
                f"of {self.size / 2**20:.1f} MiB total, highest offset {self.max_end / 2**20:.2f} MiB")


# ------------------------------------------------------------------ PKG/PFS
class HeadPkg:
    """Same key chain as fpkg_lowmem.Pkg, but over any sliceable source."""

    def __init__(self, src, keys):
        self.mm = m = src
        if m[0:4] != b"\x7fCNT":
            raise ValueError("not a PS4 PKG")
        self.content_id = m[0x40:0x64].rstrip(b"\0").decode()
        self.entry_count = struct.unpack(">I", m[0x10:0x14])[0]
        self.table_off = struct.unpack(">I", m[0x18:0x1C])[0]
        self.pfs_off, self.pfs_size = struct.unpack(">QQ", m[0x410:0x420])
        table = m[self.table_off:self.table_off + self.entry_count * 32]
        self.entries = {}
        for i in range(self.entry_count):
            raw = table[i * 32:(i + 1) * 32]
            eid, _fno, f1, f2, off, sz = struct.unpack(">IIIIII", raw[:24])
            self.entries[eid] = dict(raw=raw, flags1=f1, flags2=f2, off=off, size=sz)
        ek = self.entries[0x10]
        blob = m[ek["off"]:ek["off"] + ek["size"]]
        key3_ct = blob[32 + 7 * 32 + 3 * 256: 32 + 7 * 32 + 4 * 256]
        self.key3 = keys["pkg_key3"].decrypt(key3_ct, padding.PKCS1v15())
        self.ekpfs = keys["fake_pfs_key"].decrypt(self.entry_data(0x20), padding.PKCS1v15())

    def entry_data(self, eid):
        e = self.entries[eid]
        enc = bool(e["flags1"] & 0x80000000)
        size = (e["size"] + 15) & ~15 if enc else e["size"]
        data = self.mm[e["off"]:e["off"] + size]
        if not enc:
            return data
        ki = (e["flags2"] & 0xF000) >> 12
        if ki != 3:
            raise ValueError(f"entry 0x{eid:x} uses key index {ki}; only 3 supported")
        s = hashlib.sha256(e["raw"] + self.key3).digest()
        d = Cipher(algorithms.AES(s[16:]), modes.CBC(s[:16])).decryptor()
        return (d.update(data) + d.finalize())[: e["size"]]


class CachedPfs(Pfs):
    """Pfs with a block-map cache (base class rebuilds it on every read)."""

    def block_map(self, ino):
        cache = self.__dict__.setdefault("_bm", {})
        if ino.idx not in cache:
            cache[ino.idx] = super().block_map(ino)
        return cache[ino.idx]


def open_listing(src, keys):
    pkg = HeadPkg(src, keys)
    raw = SliceImage(src, pkg.pfs_off, pkg.pfs_size)
    hdr = raw.read_at(0, 0x380)
    mode = struct.unpack("<H", hdr[0x1C:0x1E])[0]
    bs = struct.unpack("<I", hdr[0x20:0x24])[0]
    img = XtsImage(raw, pkg.ekpfs, hdr[0x370:0x380], bs // XTS_SECTOR) if mode & 4 else raw
    outer = CachedPfs(img)
    inner = None
    for cand in ("uroot/pfs_image.dat", "pfs_image.dat"):
        try:
            inner = CachedPfs(outer.inode_image(outer.find(cand)))
            break
        except FileNotFoundError:
            continue
    return pkg, outer, inner


def normalized_path(path):
    path = "/" + path.replace("\\", "/").lstrip("/")
    if path == "/uroot":
        return "/"
    if path.startswith("/uroot/"):
        return "/" + path[len("/uroot/"):]
    return path


def align(size, bs):
    return (size + bs - 1) // bs * bs


@dataclass
class Package:
    index: int
    path: str
    content_id: str
    block_size: int
    used_inner: bool
    files: dict = field(default_factory=dict)  # path -> (size, allocated)
    source_stats: str = ""


def index_package(index, path, keys, block):
    if path.startswith(("http://", "https://")):
        src = RangeSource(path, block)
    else:
        src = FileSource(path)
    pkg, outer, inner = open_listing(src, keys)
    target = inner or outer
    files = {}
    for p, ino, is_dir in target.walk():
        if not is_dir:
            files[normalized_path(p)] = (ino.size, align(ino.size, target.bs))
    return Package(index, path, pkg.content_id, target.bs, inner is not None, files, src.stats())


# ------------------------------------------------------------------ analysis
def fmt(n):
    v = float(n)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if v < 1024 or u == "TiB":
            return f"{v:,.2f} {u}"
        v /= 1024


def pct(a, b):
    return f"{(100.0 * a / b) if b else 0.0:5.1f}%"


def report(packages, top):
    versions = defaultdict(list)  # path -> [(pkg_idx, size, alloc)]
    for pk in packages:
        for path, (size, alloc) in pk.files.items():
            versions[path].append((pk.index, size, alloc))

    sep_l = sum(v[1] for vs in versions.values() for v in vs)
    sep_a = sum(v[2] for vs in versions.values() for v in vs)
    mer_l = sum(vs[-1][1] for vs in versions.values())
    mer_a = sum(vs[-1][2] for vs in versions.values())

    cert_l = cert_a = amb_l = amb_a = 0
    replaced = []
    for path, vs in versions.items():
        for old, new in zip(vs, vs[1:]):
            certain = old[1] != new[1]
            if certain:
                cert_l += old[1]
                cert_a += old[2]
            else:
                amb_l += old[1]
                amb_a += old[2]
            replaced.append((old[2], path, old[0], new[0], old[1], new[1], certain))

    up_l, up_a = cert_l + amb_l, cert_a + amb_a

    print("\nPackages (last wins on an exact path):")
    for pk in packages:
        src = "inner PFS" if pk.used_inner else "outer PFS only"
        print(f"  {pk.index}. {pk.path}\n"
              f"     {pk.content_id} | {len(pk.files):,} files | PFS block 0x{pk.block_size:x} | {src}\n"
              f"     read: {pk.source_stats}")

    print("\nPer-update breakdown:")
    latest = {p: s for p, (s, _a) in packages[0].files.items()}
    for pk in packages[1:]:
        new = same = diff = 0
        for path, (size, _a) in pk.files.items():
            if path not in latest:
                new += 1
            elif latest[path] == size:
                same += 1
            else:
                diff += 1
        for path, (size, _a) in pk.files.items():
            latest[path] = size
        print(f"  {pk.index}. {os.path.basename(pk.path)}: {diff:,} size-changed, "
              f"{same:,} same-size (unverified), {new:,} new")

    print("\nStorage estimate (PFS-block-rounded | raw bytes):")
    print(f"  Separate packages total : {fmt(sep_a):>14} | {fmt(sep_l)}")
    print(f"  Merged result           : {fmt(mer_a):>14} | {fmt(mer_l)}")
    print(f"  Saving, LOWER bound     : {fmt(cert_a):>14} | {fmt(cert_l)}   ({pct(cert_a, sep_a)} of separate)")
    print(f"  Saving, UPPER bound     : {fmt(up_a):>14} | {fmt(up_l)}   ({pct(up_a, sep_a)} of separate)")
    print(f"  Ambiguous (same size)   : {fmt(amb_a):>14} | {fmt(amb_l)}")
    print("  Lower = only same-path files whose size changed (certainly different).")
    print("  Upper = every same-path file superseded; equals the real separate-vs-merged saving.")

    replaced.sort(reverse=True)
    if top and replaced:
        print(f"\nTop {min(top, len(replaced))} superseded files (by old allocated size):")
        for alloc, path, oi, ni, osz, nsz, certain in replaced[:top]:
            tag = "changed " if certain else "same-sz?"
            print(f"  [{tag}] {fmt(alloc):>12}  {path}  ({osz:,} -> {nsz:,} bytes, pkg {oi}->{ni})")


def main():
    ap = argparse.ArgumentParser(description="Estimate fPKG merge savings from file listings only.")
    ap.add_argument("packages", nargs="+", help="base first; head-only files, full files or http(s) URLs")
    ap.add_argument("--keys", required=True, help="orbis-pkg keys.rs")
    ap.add_argument("--top", type=int, default=10, help="show N largest superseded files (default 10)")
    ap.add_argument("--block-mb", type=float, default=1.0, help="HTTP Range block size in MiB (default 1)")
    ap.add_argument("--list", action="store_true", help="also print every file (path, size) per package")
    a = ap.parse_args()

    if not os.path.isfile(a.keys):
        ap.error(f"keys file not found: {a.keys}")
    for p in a.packages:
        if not p.startswith(("http://", "https://")) and not os.path.isfile(p):
            ap.error(f"not found: {p}")

    keys = load_rsa_keys(a.keys)
    block = max(64 << 10, int(a.block_mb * (1 << 20)))
    packages = []
    for i, p in enumerate(a.packages):
        print(f"[{i}] reading listing: {p}", file=sys.stderr)
        try:
            packages.append(index_package(i, p, keys, block))
        except NeedMoreData as e:
            print(f"\n[{i}] head file too short: needs bytes up to offset {e.needed:,} "
                  f"({e.needed / 2**20:.1f} MiB), file has {e.available:,} "
                  f"({e.available / 2**20:.1f} MiB).\n"
                  f"    Re-download a larger head (e.g. curl -r 0-{e.needed + (8 << 20) - 1} ...); "
                  f"later reads may need a bit more, so add margin.", file=sys.stderr)
            return 3
        except (OSError, ValueError, KeyError, zlib.error, struct.error) as e:
            print(f"[{i}] failed: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
        print(f"[{i}] {len(packages[-1].files):,} files; {packages[-1].source_stats}", file=sys.stderr)

    if a.list:
        for pk in packages:
            print(f"\n--- {pk.index}: {pk.path} ---")
            for path, (size, _a) in sorted(pk.files.items()):
                print(f"{size:>14,}  {path}")
    report(packages, a.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
