#!/usr/bin/env python3
"""Estimate storage savings from merging a base fPKG with related fPKGs.
Usage:
    python3 fpkg_merge_analyzer.py
    python3 fpkg_merge_analyzer.py base.pkg update.pkg dlc.pkg
        --keys keys.rs
"""

import argparse
import hashlib
import logging
import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict

# Windows 7 compatibility notes (Python 3.8 is the last version for Win7):
#  * "readline" does not exist on Windows -> optional, tab completion is skipped.
#  * Win7 consoles do not understand ANSI colors -> colors only via the optional
#    "colorama" package (pip install colorama), otherwise plain text.
#  * Python 3.8 cannot evaluate dict[str, X] annotations -> typing.Dict is used.
try:
    import readline
except ImportError:  # Windows
    readline = None

IS_WINDOWS = os.name == "nt"

from fpkg_lowmem import open_all


LOG = logging.getLogger("fpkg-merge")
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
RED = "\033[31m"
BLUE = "\033[34m"


class Styles:
    def __init__(self, enabled):
        self.enabled = enabled

    def paint(self, code, text):
        if not self.enabled:
            return text
        return f"{code}{text}{RESET}"

    def title(self, text):
        return self.paint(BOLD + BLUE, text)

    def section(self, text):
        return self.paint(BOLD + CYAN, text)

    def success(self, text):
        return self.paint(BOLD + GREEN, text)

    def warning(self, text):
        return self.paint(BOLD + RED, text)

    def emphasis(self, text):
        return self.paint(BOLD + YELLOW, text)

    def dim(self, text):
        return self.paint(DIM, text)


class ColorFormatter(logging.Formatter):
    """Color warning and error log records without polluting redirected logs."""

    def __init__(self, enabled):
        super().__init__("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S")
        self.enabled = enabled

    def format(self, record):
        text = super().format(record)
        if not self.enabled:
            return text
        if record.levelno >= logging.ERROR:
            return f"{BOLD}{RED}{text}{RESET}"
        if record.levelno >= logging.WARNING:
            return f"{BOLD}{RED}{text}{RESET}"
        if record.levelno >= logging.INFO:
            return f"{CYAN}{text}{RESET}"
        return f"{DIM}{text}{RESET}"


@dataclass(frozen=True)
class FileRecord:
    path: str
    size: int
    allocated: int
    package_index: int
    package_path: str
    digest: bytes


@dataclass
class PackageRecord:
    index: int
    path: str
    content_id: str
    block_size: int
    physical_size: int
    files: Dict[str, FileRecord]


def align(size, block_size):
    return ((size + block_size - 1) // block_size) * block_size


def display_size(size):
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size} B"


def normalized_path(path):
    """Normalize PFS paths while retaining directory identity."""
    path = "/" + path.replace("\\", "/").lstrip("/")
    if path == "/uroot":
        return "/"
    if path.startswith("/uroot/"):
        return "/" + path[len("/uroot/") :]
    return path


def extract_file_map(package_path, package_index, keys_path):
    LOG.info("[%d] opening %s", package_index, package_path)
    pkg, outer, inner = open_all(package_path, keys_path)
    target = inner or outer
    LOG.info(
        "[%d] content id=%s, PFS block=0x%x, source=%s",
        package_index,
        pkg.content_id,
        target.bs,
        "inner PFS" if inner else "outer PFS (no inner volume found)",
    )

    files = {}
    for path, inode, is_dir in target.walk():
        if is_dir:
            continue
        logical_path = normalized_path(path)
        digest = hashlib.sha256()
        position = 0
        while position < inode.size:
            chunk = target.read_inode(inode, position, min(4 << 20, inode.size - position))
            if not chunk:
                raise ValueError(f"short read while hashing {logical_path}")
            digest.update(chunk)
            position += len(chunk)
        record = FileRecord(
            path=logical_path,
            size=inode.size,
            allocated=align(inode.size, target.bs),
            package_index=package_index,
            package_path=package_path,
            digest=digest.digest(),
        )
        files[logical_path] = record

    LOG.info("[%d] indexed %d files", package_index, len(files))
    return PackageRecord(
        index=package_index,
        path=package_path,
        content_id=pkg.content_id,
        block_size=target.bs,
        physical_size=os.path.getsize(package_path),
        files=files,
    )


def package_totals(packages):
    logical = 0
    allocated = 0
    previous = {}
    for package in packages:
        for path, record in package.files.items():
            old = previous.get(path)
            if old is None or old.digest != record.digest:
                logical += record.size
                allocated += record.allocated
            previous[path] = record
    physical = sum(package.physical_size for package in packages)
    return logical, allocated, physical


def merged_records(packages):
    latest = {}
    for package in packages:
        for path, record in package.files.items():
            latest[path] = record
    return latest


def basename_candidates(packages):
    """Find same-basename files at different paths; never merge these."""
    locations = defaultdict(set)
    for package in packages:
        for path in package.files:
            locations[path.rsplit("/", 1)[-1]].add(path)
    return {
        name: sorted(paths)
        for name, paths in locations.items()
        if len(paths) > 1
    }


def print_report(packages, styles):
    merged = merged_records(packages)
    unmerged_logical, unmerged_allocated, physical = package_totals(packages)
    merged_logical = sum(record.size for record in merged.values())
    merged_allocated = sum(
        align(record.size, packages[record.package_index].block_size)
        for record in merged.values()
    )
    logical_gain = unmerged_logical - merged_logical
    allocated_gain = unmerged_allocated - merged_allocated

    print(f"\n{styles.section('Package precedence')} (last package wins on an exact path):")
    print(
        "  Scope: every regular file in the inner PFS tree; "
        "extensions are not filtered and nested formats are not parsed."
    )
    for package in packages:
        print(
            f"  {package.index}. {package.path}\n"
            f"     {package.content_id} | {len(package.files):,} files | "
            f"{display_size(package.physical_size)} on disk"
        )

    print(f"\n{styles.section('Storage estimate')}:")
    print(f"  Separate package file payloads: {display_size(unmerged_logical)}")
    print(f"  Separate PFS-rounded payloads:  {display_size(unmerged_allocated)}")
    print(f"  Separate PKG file sizes:        {display_size(physical)}")
    print(f"  Unique paths after merge:       {len(merged):,}")
    print(f"  Merged logical payload:          {display_size(merged_logical)}")
    print(f"  Merged PFS-rounded payload:     {display_size(merged_allocated)}")
    print(
        styles.success(
            f"  Estimated gain, logical:         {display_size(logical_gain)}"
        )
    )
    print(
        styles.success(
            f"  Estimated gain, PFS-rounded:    {display_size(allocated_gain)}"
        )
    )

    print(f"\n{styles.section('Overwrite analysis')}:")
    previous = {}
    replacement_count = 0
    overwritten_logical = 0
    overwritten_allocated = 0
    for package in packages:
        package_replacements = []
        new_count = 0
        shared_count = 0
        for path, record in package.files.items():
            old = previous.get(path)
            if old is None:
                new_count += 1
                continue
            if old.digest == record.digest:
                shared_count += 1
                continue
            replacement_count += 1
            overwritten_logical += old.size
            overwritten_allocated += old.allocated
            package_replacements.append((path, old, record))
        for path, record in package.files.items():
            previous[path] = record
        if package.index == 0:
            continue
        print(
            f"  {package.index}. {os.path.basename(package.path)}: "
            f"{styles.emphasis(f'{len(package_replacements):,} overwritten')}, "
            f"{styles.dim(f'{new_count:,} new')}, "
            f"{styles.dim(f'{shared_count:,} identical/shared')}"
        )
        if package_replacements:
            replaced_bytes = sum(old.size for _, old, _ in package_replacements)
            print(
                f"     old payload removed by overwrite: "
                f"{styles.paint(CYAN, display_size(replaced_bytes))}"
            )
    print(
        f"  Total exact-path overwrites: "
        f"{styles.emphasis(f'{replacement_count:,}')}"
    )
    print(
        f"  Old logical payload eliminated: "
        f"{styles.paint(CYAN, display_size(overwritten_logical))}"
    )
    print(
        f"  Old PFS-rounded payload eliminated: "
        f"{styles.paint(CYAN, display_size(overwritten_allocated))}"
    )
    print(styles.warning(
        "  WARNING: an overwrite requires the same internal path with "
        "different content; identical copies are counted once."
    ))
    print(styles.warning(
        "  NOTE: files with the same basename but different paths are "
        "distinct; merging them could corrupt the game."
    ))

    candidates = basename_candidates(packages)
    if candidates:
        print(styles.warning(
            f"\nAmbiguous basename matches (not merged): {len(candidates):,}"
        ))
        for name, paths in sorted(candidates.items()):
            print(f"  {name}:")
            for path in paths:
                print(f"    {path}")


def path_completer(text, state):
    """Complete filesystem paths while preserving spaces and typed prefixes."""
    expanded = os.path.expanduser(text)
    directory, prefix = os.path.split(expanded)
    directory = directory or "."
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        names = []
    matches = []
    for name in names:
        if not name.startswith(prefix):
            continue
        candidate = os.path.join(directory, name)
        if os.path.isdir(candidate):
            candidate += os.sep
        if expanded.startswith("~"):
            home = os.path.expanduser("~")
            candidate = candidate.replace(home, "~", 1)
        matches.append(candidate)
    return matches[state] if state < len(matches) else None


def clean_path(value):
    """Strip quotes added by drag-and-drop / 'Copy as path' on Windows."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value.strip()


def setup_console(no_color):
    """Make output safe on old Windows consoles; return True if colors are usable."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # avoid UnicodeEncodeError on odd file names
        except (AttributeError, ValueError):
            pass
    if no_color or not sys.stdout.isatty():
        return False
    if IS_WINDOWS:
        try:
            import colorama
            colorama.init()
            return True
        except ImportError:
            return False
    return True


def prompt_paths(styles):
    print(styles.title("fPKG merge analyzer"))
    print("Enter the base-game fPKG path first.")
    print("Enter update/DLC/related fPKG paths one per line; type END to begin.")
    print(styles.dim("Tip: use Up/Down history and Tab to complete paths."))
    if readline is not None:
        readline.set_completer(path_completer)
        readline.set_completer_delims("\n")
        readline.parse_and_bind("tab: complete")
    values = []
    while True:
        try:
            value = input(styles.paint(BOLD + BLUE, "fPKG path (or END): ")).strip()
        except EOFError:
            break
        except KeyboardInterrupt:
            print()
            print(styles.warning("Input cancelled."))
            return []
        value = clean_path(value)
        if value.upper() == "END":
            break
        if value:
            values.append(value)
    return values


def main():
    parser = argparse.ArgumentParser(
        description="Compare inner-PFS file maps and estimate fPKG merge savings."
    )
    parser.add_argument("packages", nargs="*", help="base first, then updates/DLCs")
    parser.add_argument("--keys", required=True, help="orbis-pkg keys.rs file")
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
        help="live diagnostic verbosity (default: INFO)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors in the report",
    )
    args = parser.parse_args()
    color_enabled = setup_console(args.no_color)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        handlers=[logging.StreamHandler()],
    )
    for handler in logging.getLogger().handlers:
        handler.setFormatter(ColorFormatter(color_enabled))

    styles = Styles(color_enabled)
    paths = [clean_path(p) for p in args.packages] or prompt_paths(styles)
    if not paths:
        parser.error("no fPKG paths supplied")
    if not os.path.isfile(args.keys):
        parser.error(f"keys file not found: {args.keys}")
    missing = [path for path in paths if not os.path.isfile(path)]
    if missing:
        parser.error("fPKG file(s) not found: " + ", ".join(missing))

    packages = []
    for index, path in enumerate(paths):
        try:
            packages.append(extract_file_map(path, index, args.keys))
        except (OSError, ValueError, KeyError, MemoryError) as exc:
            LOG.error("[%d] failed to read %s: %s", index, path, exc)
            return 2
    print_report(packages, styles)
    return 0


if __name__ == "__main__":
    sys.exit(main())
