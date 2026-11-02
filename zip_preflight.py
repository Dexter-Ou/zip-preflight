"""Read-only ZIP central-directory preflight; never extracts member contents."""
import argparse
import json
import ntpath
import stat
import unicodedata
import zipfile
from pathlib import Path

MAX_ARCHIVE = 16 * 1024 * 1024
MAX_ENTRIES = 10000


def inspect(path, max_bytes=1024 * 1024 * 1024):
    # A bounded byte snapshot prevents path replacement between size check and parse.
    import io
    with open(path, 'rb') as source:
        data = source.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise ValueError('archive exceeds 16 MiB input limit')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES:
            raise ValueError('archive exceeds 10000-entry limit')
        findings, seen, files, destinations = [], {}, set(), []
        total = sum(info.file_size for info in entries)
        for index, info in enumerate(entries):
            name = info.orig_filename
            normalized = unicodedata.normalize('NFC', name.replace('\\', '/'))
            parts = normalized.rstrip('/').split('/')
            key = '/'.join(p.rstrip(' .').casefold() for p in parts)
            codes = []
            if normalized.startswith('/') or ntpath.splitdrive(name)[0]:
                codes.append('absolute_path')
            if '..' in parts:
                codes.append('parent_segment')
            if any(p in ('', '.') for p in parts):
                codes.append('ambiguous_segment')
            if '\\' in name:
                codes.append('backslash_separator')
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
                codes.append('control_character')
            if any(p.endswith((' ', '.')) or any(ch in p for ch in ':<>"|?*') for p in parts):
                codes.append('windows_name')
            reserved = {'con', 'prn', 'aux', 'nul'} | {f'{s}{i}' for s in ('com', 'lpt') for i in range(1, 10)}
            if any(p.split('.')[0].casefold() in reserved for p in parts):
                codes.append('windows_reserved')
            kind = stat.S_IFMT(info.external_attr >> 16) if info.create_system == 3 else 0
            if kind == stat.S_IFLNK:
                codes.append('symlink')
            elif kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                codes.append('special_file')
            if info.flag_bits & 1:
                codes.append('encrypted')
            if info.compress_type not in (0, 8, 12, 14):
                codes.append('unsupported_method')
            if key in seen:
                codes.append('destination_collision')
            seen[key] = index
            destinations.append((index, name, key))
            if not info.is_dir():
                files.add(key)
            if codes:
                findings.append({'index': index, 'name': name, 'codes': codes})
        for index, name, key in destinations:
            parts = key.split('/')
            if any('/'.join(parts[:i]) in files for i in range(1, len(parts))):
                findings.append({'index': index, 'name': name, 'codes': ['file_directory_conflict']})
        if total > max_bytes:
            findings.append({'index': None, 'name': None, 'codes': ['declared_size_limit']})
        return {'status': 'review' if findings else 'no_flags', 'entries': len(entries),
                'declared_uncompressed_bytes': total, 'max_declared_bytes': max_bytes,
                'findings': findings, 'scope': 'metadata only; no safety or content-integrity guarantee'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--max-bytes', type=int, default=1024 * 1024 * 1024)
    args = parser.parse_args()
    if args.max_bytes < 0:
        parser.error('--max-bytes must be nonnegative')
    try:
        report = inspect(args.archive, args.max_bytes)
    except (OSError, ValueError, zipfile.BadZipFile, NotImplementedError) as exc:
        print(json.dumps({'status': 'error', 'error': str(exc)}, ensure_ascii=True))
        return 2
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 1 if report['findings'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
