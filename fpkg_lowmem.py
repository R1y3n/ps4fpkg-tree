#!/usr/bin/env python3
"""
fpkg_lowmem.py - low-memory reader for PS4 fake-PKG (fPKG) contents.

Chain (ported from the open-source orbis-pkg / orbis-pfs crates):
  PKG entry 0x10 (entry keys) --RSA(pkg_key3)--> entry_key3
  PKG entry 0x20 (image key)  --AES-CBC(sha256(entry||key3))--> RSA(fake_pfs_key) --> EKPFS
  EKPFS + PFS seed (hdr+0x370) --HMAC-SHA256--> XTS tweak/data keys
  outer PFS (AES-128-XTS, 4 KiB sectors) -> pfs_image.dat (PFSC/zlib) -> inner PFS -> uroot/eboot.bin

Nothing is ever fully loaded: the PKG is mmap'd, sectors/blocks are decrypted on demand,
and files are streamed to disk in chunks. Peak RAM stays in the low tens of MB.

Usage:
  fpkg_lowmem.py game.pkg --keys keys.rs --tree
  fpkg_lowmem.py game.pkg --keys keys.rs --cat uroot/eboot.bin -o eboot.bin
  fpkg_lowmem.py game.pkg --keys keys.rs --extract-all outdir/
"""
import argparse, hashlib, hmac, mmap, os, re, struct, sys, zlib
from collections import OrderedDict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

XTS_SECTOR = 0x1000


# ---------------------------------------------------------------- keys
def load_rsa_keys(path):
    """Parse the two RSA private keys out of orbis-pkg's keys.rs."""
    src = open(path, encoding="utf-8", errors="ignore").read()
    out = {}
    for fn in ("pkg_key3", "fake_pfs_key"):
        body = src.split(f"pub fn {fn}()")[1].split("RsaPrivateKey::from_components")[0]
        arrs = re.findall(r"BigUint::from_bytes_be\(&\[(.*?)\]\)", body, re.S)
        nums = [int.from_bytes(bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", a)), "big") for a in arrs]
        n, e, d, p, q = nums[0], nums[1], nums[2], nums[3], nums[4]
        priv = rsa.RSAPrivateNumbers(
            p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), rsa.rsa_crt_iqmp(p, q),
            rsa.RSAPublicNumbers(e, n))
        out[fn] = priv.private_key()
    return out


# ---------------------------------------------------------------- PKG
class Pkg:
    def __init__(self, path, keys):
        self.f = open(path, "rb")
        self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        m = self.mm
        if m[:4] != b"\x7fCNT":
            raise ValueError("not a PS4 PKG")
        self.content_id = m[0x40:0x64].rstrip(b"\0").decode()
        self.entry_count = struct.unpack(">I", m[0x10:0x14])[0]
        self.table_off = struct.unpack(">I", m[0x18:0x1C])[0]
        self.pfs_off, self.pfs_size = struct.unpack(">QQ", m[0x410:0x420])
        self.entries = {}
        for i in range(self.entry_count):
            raw = bytes(m[self.table_off + i * 32: self.table_off + (i + 1) * 32])
            eid, fno, f1, f2, off, sz = struct.unpack(">IIIIII", raw[:24])
            self.entries[eid] = dict(raw=raw, flags1=f1, flags2=f2, off=off, size=sz)
        # entry key 3
        ek = self.entries[0x10]
        blob = bytes(m[ek["off"]: ek["off"] + ek["size"]])
        key3_ct = blob[32 + 7 * 32 + 3 * 256: 32 + 7 * 32 + 4 * 256]
        self.key3 = keys["pkg_key3"].decrypt(key3_ct, padding.PKCS1v15())
        # EKPFS
        self.ekpfs = keys["fake_pfs_key"].decrypt(self.entry_data(0x20), padding.PKCS1v15())

    def entry_data(self, eid):
        e = self.entries[eid]
        enc = bool(e["flags1"] & 0x80000000)
        size = (e["size"] + 15) & ~15 if enc else e["size"]
        data = bytes(self.mm[e["off"]: e["off"] + size])
        if not enc:
            return data
        ki = (e["flags2"] & 0xF000) >> 12
        if ki != 3:
            raise ValueError(f"entry 0x{eid:x} uses key index {ki}; only 3 supported")
        s = hashlib.sha256(e["raw"] + self.key3).digest()
        iv, key = s[:16], s[16:]
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return (d.update(data) + d.finalize())[: e["size"]]


# ---------------------------------------------------------------- image layers
class SliceImage:
    def __init__(self, mm, off, size):
        self.mm, self.off, self._len = mm, off, size

    def __len__(self):
        return self._len

    def read_at(self, pos, n):
        n = max(0, min(n, self._len - pos))
        return bytes(self.mm[self.off + pos: self.off + pos + n])


class XtsImage:
    """On-demand XTS decrypt of 4 KiB sectors with a tiny LRU cache."""
    def __init__(self, src, ekpfs, seed, enc_start_sector):
        s = hmac.new(ekpfs, b"\x01\x00\x00\x00" + seed, hashlib.sha256).digest()
        tweak_key, data_key = s[:16], s[16:]
        self.key = data_key + tweak_key     # cryptography: key1(data)||key2(tweak)
        self.src, self.start = src, enc_start_sector
        self.cache = OrderedDict()

    def __len__(self):
        return len(self.src)

    def _sector(self, i):
        if i in self.cache:
            self.cache.move_to_end(i)
            return self.cache[i]
        raw = self.src.read_at(i * XTS_SECTOR, XTS_SECTOR)
        if i >= self.start:
            dec = Cipher(algorithms.AES(self.key), modes.XTS(i.to_bytes(16, "little"))).decryptor()
            raw = dec.update(raw) + dec.finalize()
        self.cache[i] = raw
        if len(self.cache) > 64:
            self.cache.popitem(last=False)
        return raw

    def read_at(self, pos, n):
        n = max(0, min(n, len(self) - pos))
        out, end = bytearray(), pos + n
        while pos < end:
            i, o = divmod(pos, XTS_SECTOR)
            chunk = self._sector(i)[o: o + (end - pos)]
            out += chunk
            pos += len(chunk)
        return bytes(out)


class PfscImage:
    def __init__(self, src):
        h = src.read_at(0, 0x30)
        if h[:4] != b"PFSC":
            raise ValueError("bad PFSC magic")
        self.src = src
        self.bs = struct.unpack("<I", h[0x0C:0x10])[0]
        self.obs = struct.unpack("<Q", h[0x10:0x18])[0]
        boff = struct.unpack("<Q", h[0x18:0x20])[0]
        self.size = struct.unpack("<Q", h[0x28:0x30])[0]
        cnt = self.size // self.obs + 1
        self.offs = struct.unpack(f"<{cnt}Q", src.read_at(boff, cnt * 8))
        self.cache = OrderedDict()

    def __len__(self):
        return self.size

    def _block(self, i):
        if i in self.cache:
            return self.cache[i]
        off, end = self.offs[i], self.offs[i + 1]
        sz = end - off
        if sz < self.obs:
            d = zlib.decompress(self.src.read_at(off, sz))
        elif sz == self.obs:
            d = self.src.read_at(off, sz)
        else:
            d = b"\0" * self.bs
        self.cache[i] = d
        if len(self.cache) > 16:
            self.cache.popitem(last=False)
        return d

    def read_at(self, pos, n):
        n = max(0, min(n, self.size - pos))
        out, end = bytearray(), pos + n
        while pos < end:
            i, o = divmod(pos, self.bs)
            chunk = self._block(i)[o: o + (end - pos)]
            out += chunk
            pos += len(chunk)
        return bytes(out)


# ---------------------------------------------------------------- PFS
class Inode:
    __slots__ = ("idx", "mode", "flags", "size", "blocks", "direct", "indirect", "signed")


class Pfs:
    def __init__(self, img):
        self.img = img
        h = img.read_at(0, 0x380)
        ver, fmt = struct.unpack("<QQ", h[:16])
        if ver != 1 or fmt != 20130315:
            raise ValueError("bad PFS header")
        self.mode = struct.unpack("<H", h[0x1C:0x1E])[0]
        self.signed = bool(self.mode & 1)
        self.encrypted = bool(self.mode & 4)
        self.bs = struct.unpack("<I", h[0x20:0x24])[0]
        self.ndinode, self.ndblock, self.ndinodeblock, self.root = struct.unpack("<QQQQ", h[0x30:0x50])
        self.seed = h[0x370:0x380]
        self._parse_inodes()

    def _parse_inodes(self):
        isz = 100 + (612 if self.signed else 68)
        self.inodes = []
        for b in range(self.ndinodeblock):
            blk = self.img.read_at(self.bs * (1 + b), self.bs)
            for o in range(0, self.bs - isz + 1, isz):
                if len(self.inodes) >= self.ndinode:
                    break
                self.inodes.append(self._inode(len(self.inodes), blk[o:o + isz]))
            if len(self.inodes) >= self.ndinode:
                break

    def _inode(self, idx, raw):
        i = Inode()
        i.idx = idx
        i.mode, _nl, i.flags, i.size = struct.unpack("<HHIQ", raw[:16])
        i.blocks = struct.unpack("<I", raw[0x60:0x64])[0]
        i.signed = self.signed
        p = raw[100:]
        step, voff = (36, 32) if self.signed else (4, 0)
        ptr = lambda k: struct.unpack("<I", p[k * step + voff: k * step + voff + 4])[0]
        i.direct = [ptr(k) for k in range(12)]
        i.indirect = [ptr(12 + k) for k in range(5)]
        return i

    def _indir(self, raw, ino):
        step, voff = (36, 32) if ino.signed else (4, 0)
        for o in range(0, len(raw) - step + 1, step):
            yield struct.unpack("<I", raw[o + voff:o + voff + 4])[0]

    def block_map(self, ino):
        n = ino.blocks
        if n == 0:
            return []
        if ino.direct[1] == 0xFFFFFFFF:
            return list(range(ino.direct[0], ino.direct[0] + n))
        m = list(ino.direct[:12])
        if n <= 12:
            return m[:n]
        raw = self.img.read_at(ino.indirect[0] * self.bs, self.bs)
        for v in self._indir(raw, ino):
            m.append(v)
            if len(m) >= n:
                return m
        raw0 = self.img.read_at(ino.indirect[1] * self.bs, self.bs)
        for a in self._indir(raw0, ino):
            raw1 = self.img.read_at(a * self.bs, self.bs)
            for v in self._indir(raw1, ino):
                m.append(v)
                if len(m) >= n:
                    return m
        raise ValueError("unsupported indirection depth")

    def read_inode(self, ino, pos, n):
        """Random access read of inode data (not PFSC-decoded)."""
        bm = self.block_map(ino)
        n = max(0, min(n, ino.size - pos))
        out, end = bytearray(), pos + n
        while pos < end:
            b, o = divmod(pos, self.bs)
            take = min(self.bs - o, end - pos)
            out += self.img.read_at(bm[b] * self.bs + o, take) if b < len(bm) else b"\0" * take
            pos += take
        return bytes(out)

    def inode_image(self, ino):
        """Expose an inode as an image (PFSC-decoded if compressed)."""
        pfs, bm = self, None

        class _I:
            def __len__(s): return ino.size
            def read_at(s, pos, n): return pfs.read_inode(ino, pos, n)
        raw = _I()
        if ino.flags & 0x1 or raw.read_at(0, 4) == b"PFSC":
            try:
                return PfscImage(raw)
            except ValueError:
                pass
        return raw

    def listdir(self, ino):
        data = self.read_inode(ino, 0, ino.size)
        res, o = [], 0
        while o + 16 <= len(data):
            i, ty, nl, es = struct.unpack("<IIII", data[o:o + 16])
            if es == 0:
                # entries never straddle blocks; skip to next block boundary
                o = (o // self.bs + 1) * self.bs
                continue
            if ty in (2, 3):
                res.append((data[o + 16:o + 16 + nl].decode("utf-8", "replace"), i, ty == 3))
            o += es
        return res

    def walk(self, ino=None, prefix=""):
        ino = self.inodes[self.root] if ino is None else ino
        for name, idx, isdir in self.listdir(ino):
            path = f"{prefix}{name}"
            child = self.inodes[idx]
            yield path, child, isdir
            if isdir:
                yield from self.walk(child, path + "/")

    def find(self, path):
        cur = self.inodes[self.root]
        for part in [p for p in path.split("/") if p]:
            for name, idx, isdir in self.listdir(cur):
                if name == part:
                    cur = self.inodes[idx]
                    break
            else:
                raise FileNotFoundError(path)
        return cur


# ---------------------------------------------------------------- open everything
def open_all(pkg_path, keys_path):
    keys = load_rsa_keys(keys_path)
    pkg = Pkg(pkg_path, keys)
    src = SliceImage(pkg.mm, pkg.pfs_off, pkg.pfs_size)
    hdr = src.read_at(0, 0x380)
    mode = struct.unpack("<H", hdr[0x1C:0x1E])[0]
    bs = struct.unpack("<I", hdr[0x20:0x24])[0]
    if mode & 4:
        img = XtsImage(src, pkg.ekpfs, hdr[0x370:0x380], bs // XTS_SECTOR)
    else:
        img = src
    outer = Pfs(img)
    # the inner image holds uroot/ (game files). Find it.
    inner = None
    for cand in ("uroot/pfs_image.dat", "pfs_image.dat"):
        try:
            inner = Pfs(outer.inode_image(outer.find(cand)))
            break
        except FileNotFoundError:
            continue
    return pkg, outer, inner


def stream_to(pfs, ino, dest, chunk=4 << 20):
    img = pfs.inode_image(ino)
    with open(dest, "wb") as f:
        pos, total = 0, len(img)
        while pos < total:
            d = img.read_at(pos, chunk)
            if not d:
                break
            f.write(d)
            pos += len(d)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pkg")
    ap.add_argument("--keys", required=True, help="orbis-pkg keys.rs")
    ap.add_argument("--tree", action="store_true")
    ap.add_argument("--cat", metavar="PATH")
    ap.add_argument("-o", "--out")
    ap.add_argument("--extract-all", metavar="DIR")
    a = ap.parse_args()

    pkg, outer, inner = open_all(a.pkg, a.keys)
    print(f"[+] content id : {pkg.content_id}", file=sys.stderr)
    print(f"[+] EKPFS      : {pkg.ekpfs.hex()}", file=sys.stderr)
    print(f"[+] outer PFS  : bs=0x{outer.bs:x} inodes={len(outer.inodes)} enc={outer.encrypted}", file=sys.stderr)
    target = inner or outer
    if inner:
        print(f"[+] inner PFS  : bs=0x{inner.bs:x} inodes={len(inner.inodes)}", file=sys.stderr)

    if a.tree or not (a.cat or a.extract_all):
        print("\n--- outer ---")
        for p, ino, d in outer.walk():
            print(f"{'D' if d else 'F'} {ino.size:>12}  {p}")
        if inner:
            print("\n--- inner (game content) ---")
            for p, ino, d in inner.walk():
                print(f"{'D' if d else 'F'} {ino.size:>12}  {p}")
    if a.cat:
        ino = target.find(a.cat)
        stream_to(target, ino, a.out or os.path.basename(a.cat))
        print(f"[+] wrote {a.out or os.path.basename(a.cat)}", file=sys.stderr)
    if a.extract_all:
        for p, ino, d in target.walk():
            dst = os.path.join(a.extract_all, p)
            if d:
                os.makedirs(dst, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                stream_to(target, ino, dst)
                print(f"    {p}", file=sys.stderr)


if __name__ == "__main__":
    main()
