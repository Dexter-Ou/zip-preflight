# ZIP Preflight

Free, MIT-licensed preview from Gong LLC.

Read a ZIP central directory and report selected extraction concerns as JSON.
Requires Python 3.12 or newer; no third-party dependencies. Linux testing only.

Download this repository using GitHub’s Code → Download ZIP, extract it into a
trusted directory, and open a terminal there. No installation is needed.

```sh
python3 -c "import zipfile; z = zipfile.ZipFile('example.zip', 'w'); z.writestr('hello.txt', 'hello'); z.close()"
python3 zip_preflight.py example.zip --max-bytes 1073741824
```

The example reports one entry, five declared bytes and `no_flags`. Replace
`example.zip` with your archive to inspect it.
Exit 0 means no selected flags, 1 means review flags, 2 means input/argument error.
Run synthetic checks with `python3 -m unittest -v` from this directory.

The tool reads up to 16 MiB of archive bytes and accepts at most 10,000 entries.
It never extracts or decompresses members. Declared sizes are untrusted metadata.
It flags parent/absolute paths, portable destination collisions, selected Windows
names, symlinks/special entries, encryption, and declared total-size excess.

This is an advisory metadata report, not a secure extraction tool, malware scanner,
CRC check or proof an archive is safe. No nested archive, existing destination,
local-header consistency, actual expanded-size or filesystem behavior checks.
Case/Unicode comparison is deliberately conservative and may overflag on Linux.
Resource bounds are input caps, not a sandbox; use an isolated process for hostile
files. Python's parser still processes central-directory metadata in memory.
Names in JSON use escapes for terminal control characters. Reports may contain
private filenames; choose where to store/share them.

Recovery: retain your original ZIP; this program opens it read-only. Remove this
source directory to uninstall. It creates no service, account or persistent task.

For a reproducible producer workflow, see [Check a ZIP before publishing it](RELEASE-CHECK.md).
