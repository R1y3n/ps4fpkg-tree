#!/usr/bin/env python3
"""Print a Linux-style tree for a PS4 fPKG and its game asset manifest.

The PFS reader decrypts the PKG layers.  data-ps4.pak is a game-specific
archive, so this tool expands its virtual paths from manifest-data.xml while
leaving the PAK bytes untouched.

Usage:
  ./fpkg_tree.py test.pkg --keys keys.rs
"""

import argparse
import re
import sys

from fpkg_lowmem import open_all


NODE_RE = re.compile(
    rb"<node\s+id=(['\"])(.*?)\1([^>]*)/?>", re.DOTALL
)
ATTR_RE = re.compile(rb"\b([A-Za-z_][A-Za-z0-9_-]*)=(['\"])(.*?)\2")


def manifest_entries(data):
    """Return (path, metadata) entries from the resource manifest."""
    entries = []
    for match in NODE_RE.finditer(data):
        path = match.group(2).decode("utf-8", "replace")
        attrs = {
            key.decode("ascii"): value.decode("utf-8", "replace")
            for key, _, value in ATTR_RE.findall(match.group(3))
        }
        entries.append((path, attrs))
    return entries


def format_size(size):
    return f"{size:,} bytes"


def print_physical_tree(pfs):
    nodes = {"uroot": ({}, None)}
    for path, inode, is_dir in pfs.walk():
        current = nodes
        parts = ["uroot"] + path.split("/")
        for part in parts[:-1]:
            current = current.setdefault(part, ({}, None))[0]
        current[parts[-1]] = ({}, (inode, is_dir))

    def walk(node, prefix=""):
        names = sorted(node)
        for pos, name in enumerate(names):
            last = pos == len(names) - 1
            children, info = node[name]
            branch = "└── " if last else "├── "
            suffix = ""
            if info is not None:
                inode, is_dir = info
                suffix = "/" if is_dir else f"  [{format_size(inode.size)}]"
            print(f"{prefix}{branch}{name}{suffix}")
            if children:
                walk(children, prefix + ("    " if last else "│   "))

    walk(nodes)


def print_asset_tree(entries, pak_size):
    tree = {}
    metadata = {}
    for path, attrs in entries:
        if not path or path.startswith("/"):
            continue
        current = tree
        parts = [part for part in path.split("/") if part not in ("", ".")]
        for part in parts:
            current = current.setdefault(part, {})
        metadata[path] = attrs

    print(f"\nvirtual assets in data-ps4.pak  [{format_size(pak_size)}]")
    print(f"├── PAK.V11  [archive header]")
    print(f"└── manifest resources  [{len(metadata):,} paths]")

    def walk(node, path_prefix="", display_prefix="    "):
        names = sorted(node)
        for pos, name in enumerate(names):
            last = pos == len(names) - 1
            path = f"{path_prefix}/{name}" if path_prefix else name
            child = node[name]
            marker = "└── " if last else "├── "
            if child:
                print(f"{display_prefix}{marker}{name}/")
                walk(
                    child,
                    path,
                    display_prefix + ("    " if last else "│   "),
                )
            else:
                attrs = metadata.get(path, {})
                dimensions = ""
                if "w" in attrs and "h" in attrs:
                    dimensions = f", {attrs['w']}x{attrs['h']}"
                print(
                    f"{display_prefix}{marker}{name}"
                    f"  [PAK asset{dimensions}]"
                )

    walk(tree)


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt an fPKG and print its PFS and PAK asset tree."
    )
    parser.add_argument("pkg", help="PS4 fPKG/PKG file")
    parser.add_argument("--keys", required=True, help="keys.rs file")
    parser.add_argument(
        "--no-assets",
        action="store_true",
        help="only print files physically stored in the PFS",
    )
    args = parser.parse_args()

    try:
        pkg, outer, inner = open_all(args.pkg, args.keys)
        target = inner or outer
        print(f"{pkg.content_id}/")
        print_physical_tree(target)

        if not args.no_assets and inner is not None:
            try:
                manifest_ino = inner.find("uroot/manifest-data.xml")
                manifest = inner.read_inode(
                    manifest_ino, 0, manifest_ino.size
                )
                pak_ino = inner.find("uroot/data-ps4.pak")
            except FileNotFoundError:
                print(
                    "\n(no manifest-data.xml/data-ps4.pak found; "
                    "no virtual asset tree)",
                    file=sys.stderr,
                )
            else:
                print_asset_tree(manifest_entries(manifest), pak_ino.size)
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
