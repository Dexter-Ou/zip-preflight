# Check a ZIP before publishing it

Run ZIP Preflight against a candidate release before distributing it. This
metadata-only check can highlight names that collide when compared without case.
Use Python 3.12+ in a trusted directory containing `zip_preflight.py`.

## Reproduce a naming collision

The following creates two small synthetic archives in a temporary directory.
It inspects them without extracting members and deletes the fixtures afterward.

```sh
python3 - <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

with tempfile.TemporaryDirectory() as directory:
    for filename, notice in [("collision.zip", "DEPENDENCIES"),
                             ("renamed.zip", "DEPENDENCIES.txt")]:
        archive = Path(directory) / filename
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("dependencies/", "")
            output.writestr(notice, "notice")
        before = hashlib.sha256(archive.read_bytes()).hexdigest()
        result = subprocess.run(
            [sys.executable, "zip_preflight.py", str(archive)],
            capture_output=True, text=True,
        )
        report = json.loads(result.stdout)
        codes = [code for finding in report["findings"]
                 for code in finding["codes"]]
        print(filename, "exit", result.returncode, report["status"], codes)
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == before
        if filename == "collision.zip":
            assert result.returncode == 1 and "destination_collision" in codes
        else:
            assert result.returncode == 0 and report["status"] == "no_flags"
PY
```

Expected output:

```text
collision.zip exit 1 review ['destination_collision']
renamed.zip exit 0 no_flags []
```

This naming pattern is motivated by the historical Apache Directory Server
issue [DIRSERVER-2100](https://issues.apache.org/jira/browse/DIRSERVER-2100),
resolved in October 2015: a directory named `dependencies` and a file named
`DEPENDENCIES` conflicted on case-insensitive systems. The example above is a
synthetic reconstruction with a rename control, not the original Apache archive
or its historical fix. It was tested on Linux with Python 3.12.15; Windows and
macOS extraction behavior was not tested.

## Inspect your candidate

From the source directory, replace `candidate.zip` with your candidate's path:

```sh
python3 zip_preflight.py candidate.zip --max-bytes 1073741824
```

Exit 0 means no selected metadata flags; 1 means review the findings; 2 means
an input or argument error. Review exit 1 and 2 before continuing your release
process. Fix names in the packaging inputs, rebuild the ZIP, and rerun the check.
The command does not repair or extract archives. Keep the original artifact.

An exit 0 is not a safe-extraction or content-integrity guarantee. Declared sizes
are untrusted. The command caps archive bytes at 16 MiB and entries at 10,000;
it does not check contents, CRCs, nested archives, existing destination files,
actual expanded sizes or filesystem behavior. Conservative case/Unicode matching
can overflag. Use an isolated process for hostile inputs; these caps are not a
sandbox. Reports can contain private filenames. See [README.md](README.md) for
full scope and removal instructions.
