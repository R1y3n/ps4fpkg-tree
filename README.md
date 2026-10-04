# PS4 fPKG Inner-PFS Tools

Utilities for inspecting PS4 fake PKG (`fPKG`) files and estimating how much
space could be saved by combining a base game with later updates or add-on
packages.

The tools inspect the decrypted **inner PFS** file tree. This is important
because the inner PFS contains the actual application files, including
executables, libraries, Unity files, resource sidecars, archives, and other
game data. The outer PKG table contains package metadata and references to the
PFS image; it is not the complete game file list.

> **Use only with software and keys you are authorized to inspect.**

## Included programs

### `fpkg_merge_analyzer.py`

Compares a base fPKG with any number of later packages and estimates the
storage reduction from merging them into one logical file set.

It:

- decrypts and opens each package's inner PFS;
- indexes every regular file in the inner PFS directory tree;
- hashes each file with SHA-256;
- treats the input order as version precedence;
- treats a later file as an overwrite only when its full internal path matches
  and its content differs;
- counts byte-identical copies only once;
- retains files that exist only in later packages;
- includes PFS block rounding in the padded estimate;
- reports ambiguous basename matches without merging them;
- supports interactive path entry, readline history, and filesystem Tab
  completion;
- provides colored terminal output and live diagnostic logging.

The analyzer does **not** parse proprietary data inside files such as `.pak`,
`.rpf`, `.bank`, Unity `.assets`, `.resS`, `.resource`, or custom `.bin`
files. Each of those is compared as one complete inner-PFS file. This matches
the storage model being estimated: a later package replaces an earlier file
path, rather than selectively replacing unknown records inside that file.

### `fpkg_tree.py`

Prints a Linux-style tree of the decrypted PFS contents. It also prints a
virtual asset tree when `manifest-data.xml` is available. That virtual tree
describes paths listed by the manifest; it does not unpack proprietary archive
bytes.

### `fpkg_lowmem.py`

The lower-level package/PFS reader used by both utilities. It decrypts the
PKG/PFS layers on demand and avoids loading the entire package or PFS image
into memory.

## Requirements

- Linux or another POSIX-like environment
- Python 3.10 or newer recommended
- Python package: `cryptography`
- The package's authorized RSA key material in the expected `keys.rs` format

Install the Python dependency in a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install cryptography
```

The tools use the standard-library `readline` module for interactive editing
and completion. On some minimal Linux installations it may be necessary to
install the platform readline development/runtime package through the system
package manager.

## Quick start

Make the scripts executable if desired:

```bash
chmod +x fpkg_merge_analyzer.py fpkg_tree.py
```

Analyze a base package and one update interactively:

```bash
python3 fpkg_merge_analyzer.py --keys keys.rs
```

The program asks for the base package first, then any related update, DLC, or
other package. Type `END` when all paths have been entered:

```text
fPKG path (or END): ./fictional-space-game-v1.00.pkg
fPKG path (or END): ./fictional-space-game-v1.01.pkg
fPKG path (or END): ./fictional-space-game-expansion.pkg
fPKG path (or END): END
```

Use the arrow keys to edit the current path or recall previous entries. Press
Tab to complete a directory or filename.

## Non-interactive usage

Package order is significant. The first path is the base; every following
path is newer and has precedence over earlier packages:

```bash
python3 fpkg_merge_analyzer.py \
  "./fictional-space-game-v1.00.pkg" \
  "./fictional-space-game-v1.01.pkg" \
  "./fictional-space-game-expansion.pkg" \
  --keys ./keys.rs
```

Use an absolute key path when running the command from another directory:

```bash
python3 /opt/fpkg-tools/fpkg_merge_analyzer.py \
  "/data/games/fictional-space-game-v1.00.pkg" \
  "/data/games/fictional-space-game-v1.01.pkg" \
  --keys "/opt/fpkg-tools/keys.rs"
```

## Logging and terminal output

The default logging level is `INFO`:

```bash
python3 fpkg_merge_analyzer.py \
  "./fictional-space-game-v1.00.pkg" \
  --keys ./keys.rs \
  --log-level INFO
```

Available levels:

```text
DEBUG      additional diagnostic detail
INFO       package opening and indexing progress
WARNING    warnings
ERROR      failures
```

Disable ANSI colors for logs, redirected output, or scripts:

```bash
python3 fpkg_merge_analyzer.py \
  "./fictional-space-game-v1.00.pkg" \
  "./fictional-space-game-v1.01.pkg" \
  --keys ./keys.rs \
  --no-color \
  --log-level WARNING
```

## Understanding the merge model

Suppose the base package contains:

```text
/usr/app/fictional/main.pak       40 MB
/usr/app/fictional/base.dat       12 MB
```

and the update contains:

```text
/usr/app/fictional/main.pak       60 MB
/usr/app/fictional/update.dat      5 MB
```

The logical merged result is:

```text
/usr/app/fictional/main.pak       60 MB  <- update replaces base file
/usr/app/fictional/base.dat       12 MB  <- retained
/usr/app/fictional/update.dat      5 MB  <- update-only file
```

The separate payload is:

```text
40 + 12 + 60 + 5 = 117 MB
```

The merged payload is:

```text
60 + 12 + 5 = 77 MB
```

The estimated logical saving is therefore:

```text
117 - 77 = 40 MB
```

The update file being larger does not reduce the overwrite saving. The old
40 MB base file is eliminated, while the newer 60 MB file remains.

### Exact path matching

Only the complete normalized internal path identifies a file:

```text
/Media/Managed/mono/2.0/machine.config
/Media/Managed/mono/4.0/machine.config
```

These are different files even though their basenames are both
`machine.config`. The analyzer reports such cases as ambiguous and does not
merge them.

### Identical files

If the same path and content occur in two packages, the later copy is not
counted as an overwrite:

```text
Base:   /usr/app/shared.dat  10 MB
Update: /usr/app/shared.dat  10 MB, identical bytes
```

The analyzer counts one 10 MB logical file and reports:

```text
0 overwritten
1 identical/shared
0 B gain for that path
```

### Later versions

For three inputs:

```text
base.pkg
update-v1.pkg
update-v2.pkg
```

`update-v2.pkg` wins over `update-v1.pkg`, and `update-v1.pkg` wins over the
base when the same internal path has different content. If a later package
contains an identical copy, it is shared rather than overwritten.

## Example analyzer output

The following uses fictional package names and illustrative values:

```text
Package precedence (last package wins on an exact path):
  Scope: every regular file in the inner PFS tree; extensions are not filtered
         and nested formats are not parsed.
  0. fictional-space-game-v1.00.pkg
     FA0000-CUSA00000_00-FICTIONALGAME000 | 452 files | 1.42 GiB on disk
  1. fictional-space-game-v1.01.pkg
     FA0000-CUSA00000_00-FICTIONALGAME000 | 217 files | 612.00 MiB on disk

Storage estimate:
  Separate package file payloads:  3.80 GiB
  Separate PFS-rounded payloads:   4.10 GiB
  Separate PKG file sizes:          2.03 GiB
  Unique paths after merge:         453
  Merged logical payload:            3.05 GiB
  Merged PFS-rounded payload:       3.25 GiB
  Estimated gain, logical:         770.00 MiB
  Estimated gain, PFS-rounded:    870.00 MiB

Overwrite analysis:
  1. fictional-space-game-v1.01.pkg: 214 overwritten, 1 new, 2 identical/shared
     old payload removed by overwrite: 770.00 MiB
  Total exact-path overwrites: 214
  Old logical payload eliminated: 770.00 MiB
  Old PFS-rounded payload eliminated: 870.00 MiB
```

Values in this example are fictional and are not tied to an official title.

## Inspecting a package tree

Print the decrypted physical tree:

```bash
python3 fpkg_tree.py \
  "./fictional-space-game-v1.00.pkg" \
  --keys ./keys.rs
```

The output includes files such as:

```text
FICTIONAL-CONTENT-ID/
└── uroot/
    ├── eboot.bin
    ├── Media/
    │   ├── level0
    │   ├── resources.assets
    │   ├── sharedassets1.resource
    │   └── Managed/
    │       └── FictionalGame.dll
    └── sce_module/
        └── fictional-module.prx
```

Only the physical PFS entries are printed with `--no-assets`:

```bash
python3 fpkg_tree.py \
  "./fictional-space-game-v1.00.pkg" \
  --keys ./keys.rs \
  --no-assets
```

## What the size fields mean

The analyzer reports three different concepts:

### Separate package file sizes

The byte sizes of the original PKG files on disk. These include PKG metadata,
PFS structures, encryption-related data, alignment, and other container
overhead. They are useful for comparing the source packages, but they are not
the exact size of a newly rebuilt merged PKG.

### Logical payload

The sum of the regular inner-PFS file sizes after applying the overwrite model.
This is the most direct estimate of content bytes retained or eliminated.

### PFS-rounded payload

Each retained/replaced file is rounded up to the package PFS block size before
being summed. This better models filesystem allocation than a raw byte sum.
It still excludes merged-container overhead such as new headers, inode tables,
directory blocks, signatures, and implementation-specific allocation details.

Consequently, the PFS-rounded figure is the preferred storage estimate, while
the exact final size of a rebuilt package can differ.

## How the package is read

The reader follows this simplified chain:

```text
fPKG
└── outer PKG metadata
    └── encrypted outer PFS
        └── pfs_image.dat
            └── inner PFS
                └── uroot file tree
```

The analyzer reads the inner PFS inode and directory structures, then hashes
regular files in chunks. It does not need to extract every file to disk.

## Operational notes

- Input order is the version order. Put the base first.
- A missing or unreadable path stops processing with an error.
- A missing `keys.rs` path is rejected before package processing.
- The analyzer keeps only metadata and hashes in its comparison dictionaries;
  it does not retain every file's full content.
- Hashing large files requires reading their data through the decrypted PFS
  reader, so `INFO` messages show progress at package boundaries.
- The program does not rebuild or modify PKG files.
- The program does not claim that same-named files at different paths are
  interchangeable.
- `Ctrl-C` during interactive entry cancels input cleanly.

## Troubleshooting

### `cryptography` is missing

Create or activate a virtual environment and install the dependency:

```bash
. .venv/bin/activate
python3 -m pip install cryptography
```

### The package cannot be opened

Check that:

1. the path is correct;
2. the file is a supported PS4 PKG/fPKG;
3. the supplied authorized key file matches the expected `keys.rs` format;
4. the process has read permission for both the package and key file.

### Tab completion does not work

The interactive analyzer uses Python's `readline` module. Confirm that the
program is running in a real terminal rather than through a pipe or a shell
without readline support. Non-interactive usage with explicit paths is always
available.

### Why is the gain different from the PKG file-size difference?

PKG files include container overhead and may use different compression,
alignment, and metadata layouts. The analyzer estimates merged inner-PFS
content storage, not the exact result of a particular PKG-building tool.

## Command reference

### Merge analyzer

```text
python3 fpkg_merge_analyzer.py [PACKAGE ...] --keys KEYS

Options:
  --keys PATH
      Authorized keys.rs file required to decrypt/read the package.
  --log-level {DEBUG,INFO,WARNING,ERROR}
      Live diagnostic verbosity. Default: INFO.
  --no-color
      Disable ANSI colors.
  -h, --help
      Show command help.
```

With no positional packages, the program enters interactive mode. With one or
more positional packages, it processes them directly in the supplied order.

### Tree printer

```text
python3 fpkg_tree.py PACKAGE --keys KEYS [--no-assets]

Options:
  --keys PATH
      Authorized keys.rs file.
  --no-assets
      Print only the physical PFS tree and skip manifest-based virtual assets.
```

## License and project status

This repository contains utilities for local file-format analysis. No official
game assets are included in the documentation examples. Review and apply the
license terms for the repository and all dependencies before redistribution.
