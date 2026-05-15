synology-decrypt
================

# Goal

An open source implementation/description of the encryption/decryption
algorithm used by Synology NAS products in their Cloud Sync feature, where one
can sync data on the NAS to the likes of Google Drive.

Synology publishes a closed source tool (see below), but I would like to be
know how to decrypt my own data with my own password or private key, in the
(unlikely) event that I lose access to both a NAS of this type and the closed
source tool.

Also, I would like to be able to judge the strength of the encryption.

Official documentation of the encryption algorithm exists, but only on a high
level, and the file format is not documented at all.

I've chosen Python, since I think that allows to to express the algorithm most
clearly.

(Please note that I explicitly do not want to reverse engineer the closed
source 'Synology Cloud Sync Decryption Tool', since I want to avoid doing
things that might be construed to be illegal.)


# How to install and run

You need to download the source code and install a few dependencies:

* `git clone` this repository.
* Make sure you have Python installed (3.2 or later, or 2.7); Linux works, I've never tried it on Windows but that should also Just Work(tm).
* Install all Python packages which are mentioned in `requirements.txt`, e.g. by running `pip install -r requirements.txt`.
* Make sure you have **the `lz4` binary** on your `PATH`.
   - On Ubuntu (at least 18.04) you can install it by running `apt install liblz4-tool` as root.

This is a command line tool, and running it comes down to the following.

* In the root folder of the cloned repository, run `python -m syndecrypt` followed by the supported command line arguments (leave out or add `-h` for usage information / help).

The tool now supports directories (scanned recursively) and zip files as input. If no password file or private key is provided, the tool will prompt for a password interactively.

## Preserving metadata (`-a` / `--archive`)

Pass `-a` (or `--archive`) to copy filesystem metadata from each source onto the decrypted output, similar to `rsync -a`. The following are preserved:

* file mode bits (`chmod`)
* modification time (`mtime`) and access time (`atime`), with nanosecond precision for file/directory inputs (second precision for entries inside a zip)
* owner and group (`uid` / `gid`), if the running user is permitted to change them — typically only `root` or a process with `CAP_CHOWN`. When not permitted, ownership is silently left as the running user, the same way `rsync` handles it.

For zip-file input, only `mode` (when the archive was produced on Unix) and `mtime` are present in standard zip metadata; `atime`, `uid`, and `gid` are not preserved.

`ctime` (inode change time) **cannot** be preserved: it is not settable by any Linux syscall and is updated by the kernel whenever an inode is modified. This matches the behavior of `rsync` and other archival tools.

`--archive` is a no-op when combined with `--verify` (no output file is produced).

## Excluding files by size (`--skip-larger-than` / `--skip-smaller-than`)

Two optional flags let you **exclude** files at the size extremes — useful on low-RAM hardware (e.g., a Synology NAS) where you'd rather not pull multi-GB files through LZ4 decompression, or when you only want to process files within a particular size band.

These are **exclusion** filters: they drop files that match, they do not select them. Naming them `--skip-...` is intentional so the direction is unambiguous.

* `--skip-larger-than=SIZE` — exclude any input file whose size is **strictly greater than** `SIZE`. (Keep only files of size ≤ `SIZE`.)
* `--skip-smaller-than=SIZE` — exclude any input file whose size is **strictly less than** `SIZE`. (Keep only files of size ≥ `SIZE`.)

Either may be used alone, or both together to define a kept-range. The comparison is strict, so a file whose size exactly equals the threshold is **kept**, not excluded.

`SIZE` accepts a plain byte count or a binary-prefix suffix (case-insensitive):

| Example | Bytes |
|---------|-------|
| `1024`  | 1024  |
| `1K`    | 1024  |
| `1.5K`  | 1536  |
| `1M`    | 1 048 576 |
| `1G`    | 1 073 741 824 |
| `1T`    | 1 099 511 627 776 |

**Important:** the comparison is against the **encrypted (on-disk) size** — the `.csenc` file size, or the uncompressed entry size when reading from a zip. csenc files are LZ4-compressed, so the decrypted output is usually larger than what the filter sees. If you need to gate by decrypted size, decrypt without a filter and post-process.

These exclusions apply in `--verify` mode too — excluded files are dropped before any decompression work runs.

Example — only process files between 1 KB and 100 MB inclusive:

```
python -m syndecrypt -p password.txt \
    --skip-larger-than=100M --skip-smaller-than=1K \
    -O out/ encrypted/
```

The summary at the end of the run lists how many files were excluded:

```
Decrypted 12 file(s): all succeeded. (4 excluded by --skip-larger-than/--skip-smaller-than.)
```

## Atomic output (`.partial` rename)

Decrypted output is first written to `<name>.partial` in the destination directory, then renamed to `<name>` only after the decrypt completes. If the process is killed mid-stream (SIGKILL, OOM-kill, power loss), you are left with a clearly-labeled `<name>.partial` rather than a truncated file under the final name. The "already exists" guard only checks the final name, so a stale `.partial` from a previous failed run is silently overwritten on the next attempt.

The rename is atomic only when source and destination are on the same filesystem, which is guaranteed here since both paths sit in the same output directory.

# Feedback

Feel very free to create a GitHub issue, create a pull request, or drop me a
line, if you have any opinions, bug reports, requests, or whatever about this
project.  Thanks!

# Build Status

Travis CI says: [![Build
Status](https://travis-ci.org/marnix/synology-decrypt.svg?branch=master)](https://travis-ci.org/marnix/synology-decrypt)

Codacy says: [![Codacy Badge](https://api.codacy.com/project/badge/Grade/f0a4a700858b4795829b02d5156b6075)](https://www.codacy.com/app/marnix-klooster-github-com/synology-decrypt?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=marnix/synology-decrypt&amp;utm_campaign=Badge_Grade)

# License

The code in this repository is licensed under the GPLv3; see LICENSE.txt for
details.

# Information Sources

There are four pieces of information from Synology, unfortunately spread out
over multiple places which are not easy to find, and not linked together at
all:

 * 'Synology Cloud Sync Decryption Tool', the closed source decryption tool
   (Windows and Linux only, apparently GUI only) which Synology provides.

   It can be obtained through the Synology Support Download Center at
   https://www.synology.com/en-us/support/download/, then choose a NAS that
   offers Cloud Sync (many of them, e.g.,
   [DS110j](https://www.synology.com/en-us/support/download/DS110j)).

   As of this writing the current version is 009.

   (The GUI has a help icon that opens
   https://help.synology.com/enu/utility/SynologyCloudSyncDecryptionTool which
   which contains the same infor as the KB article below.  It also returns
   404 fairly often.)

 * Synology Knowledge Base article ["What is Synology Cloud Sync Decryption
   Tool?"](https://www.synology.com/en-global/knowledgebase/DSM/tutorial/Application/What_is_Synology_Cloud_Sync_Decryption_Tool)
   describing how to use the above decryption tool.

 * Page 9 of ["Cloud Sync White Paper -- Based on DSM
   6.0"](https://global.download.synology.com/download/Document/WhitePaper/Synology_Cloud_Sync_White_Paper-Based_on_DSM_6.0.pdf)
([archive.org copy](https://web.archive.org/web/20160606190954/https://global.download.synology.com/download/Document/WhitePaper/Synology_Cloud_Sync_White_Paper-Based_on_DSM_6.0.pdf))
   which I received through Synology Support.

 * The Synology NAS software just lets me check an 'encrypt' checkbox and asks
   for a password, and then sends back a zip-file `key.zip` with files
   `public.pem` and `private.pem`, without any explanation what I can/should do
   with it.

   The above documents make it clear that the files are encrypted individually,
   and that each file can be decrypted using only the password or only
   `private.pem`.

Until now, there is only one unofficial source of information:

 - The answers and comments on my StackOverflow question: [What decryption algorithm is
   used here?](http://security.stackexchange.com/q/124838/3617).

# To Do

The current code is still basic and does not provide enough explanation yet.  I'd still like to do the following:

## Core decryption algorithm

* Investigate what key2_hash is a hash of.
* Warn for any known field that is missing, and for every unknown field.
* Rename `core` to `algorithm`?
* Full documentation of the algorithm in the 'core' module.
* Add algorithm diagram.
* Support `encrypt` = 0 and `compress` = 0 modes.  (It is an error if either of these fields is not specified.)
* Add verification of `@SynologyCloudSync/cloudsync_encrypt.info` file using password and/or private key.
* Investigate how DSM GUI handles non-ASCII passwords.

## Command-line decryption tool

* ~~Decrypt directories recursively.~~ *(done)*
* Check password file: check single line, warning if not printable ASCII.
* Make log level configurable (default: warning).
* ~~Add `--verify` option, to check decryptability and file structure.~~ *(done)*
* Make `--verify` option also verify `@SynologyCloudSync/cloudsync_encrypt.info` files.

## Encryption

* Add encryption option/algorithm.

# Changelog

## 2026-05-15

* **Atomic output writes**: decrypted output is now staged as `<name>.partial` and renamed on success, so abrupt termination (SIGKILL, OOM-kill, power loss) no longer leaves a truncated file under the final name. See "Atomic output" above.

## 2026-05-14

* **`-a` / `--archive` option**: Optionally preserve source filesystem metadata (mode, mtime, atime, and uid/gid when permitted) on decrypted output, similar to `rsync -a`. See "Preserving metadata" above.
* **`--skip-larger-than` / `--skip-smaller-than` options**: Optionally exclude input files outside a size window, evaluated against the encrypted on-disk size before any decompression work. The `skip-` prefix is intentional: these are exclusion filters, not selection filters. SIZE accepts K/M/G/T binary suffixes. The run summary now reports an excluded count alongside succeeded/failed. See "Excluding files by size" above.

## 2026-04-12

* **Directory input**: When an input path is a directory, all files are now scanned recursively and decrypted into the output directory with their directory structure preserved.
* **Zip file input**: When an input path is a zip file (e.g., downloaded from Google Drive), encrypted files inside the archive are decrypted directly from the zip stream. No temporary files are written to disk, ensuring previously-protected data is not left behind.
* **`--verify` option**: New flag to check decryptability and file structure without actually writing decrypted output. Works with files, directories, and zip archives.
* **Interactive password prompt**: When neither `-p` (password file) nor `-k` (private key) is provided, the tool now prompts for a password on the console using `getpass` (input is not echoed).
* **Absolute path handling**: Input files specified with absolute paths now produce correct output paths relative to the output directory, instead of being treated as the root of the filesystem.
* **Default output directory**: The `-O` / `--output-directory` option now defaults to `output` in the current working directory, so it no longer needs to be specified explicitly.
