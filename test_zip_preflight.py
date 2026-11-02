import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from unittest.mock import patch
from zip_preflight import inspect


class JourneyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'input.zip'

    def make(self, entries):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(self.path, 'w', zipfile.ZIP_DEFLATED) as z:
                for name, content in entries:
                    z.writestr(name, content)

    def codes(self):
        return {c for f in inspect(self.path)['findings'] for c in f['codes']}

    def test_clean_and_no_content_read(self):
        self.make([('docs/', ''), ('docs/readme.txt', 'hello')])
        before = self.path.read_bytes()
        with patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('content read')):
            self.assertEqual(inspect(self.path)['status'], 'no_flags')
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.path.parent.iterdir()), ['input.zip'])

    def test_paths_and_control_output(self):
        self.make([(n, '') for n in ['../escape', '/root', 'C:/drive', 'a\\b', 'a\nb', 'a/./b']])
        self.assertTrue({'parent_segment', 'absolute_path', 'backslash_separator', 'control_character', 'ambiguous_segment'} <= self.codes())
        q = subprocess.run([sys.executable, 'zip_preflight.py', str(self.path)], capture_output=True, text=True)
        self.assertEqual(q.returncode, 1)
        self.assertEqual(json.loads(q.stdout)['status'], 'review')
        self.assertIn('a\\nb', q.stdout)

    def test_portable_collisions(self):
        self.make([(n, '') for n in ['A.txt', 'a.txt', 'e\u0301.txt', '\u00e9.txt', 'trailing.', 'trailing']])
        self.assertIn('destination_collision', self.codes())
        self.assertIn('windows_name', self.codes())

    def test_symlink_and_file_parent(self):
        link = zipfile.ZipInfo('link'); link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.make([(link, '../target'), ('a', ''), ('a/b', '')])
        self.assertTrue({'symlink', 'file_directory_conflict'} <= self.codes())

    def test_size_and_reserved(self):
        self.make([('CON.txt', 'x' * 100)])
        self.assertIn('windows_reserved', self.codes())
        self.assertIn('declared_size_limit', {c for f in inspect(self.path, 99)['findings'] for c in f['codes']})

    def test_invalid_cli(self):
        self.path.write_bytes(b'not zip')
        q = subprocess.run([sys.executable, 'zip_preflight.py', str(self.path)], capture_output=True, text=True)
        self.assertEqual(q.returncode, 2)
        self.assertEqual(json.loads(q.stdout)['status'], 'error')

    def test_bounds(self):
        self.make([('a', '')])
        with patch('zip_preflight.MAX_ENTRIES', 0):
            with self.assertRaisesRegex(ValueError, 'entry limit'):
                inspect(self.path)
        with patch('zip_preflight.MAX_ARCHIVE', 2):
            with self.assertRaisesRegex(ValueError, 'input limit'):
                inspect(self.path)

    def test_encrypted_metadata(self):
        self.make([('a', 'hello')])
        data = bytearray(self.path.read_bytes())
        for sig, offset in [(b'PK\x03\x04', 6), (b'PK\x01\x02', 8)]:
            i = data.index(sig) + offset
            data[i] |= 1
        self.path.write_bytes(data)
        self.assertIn('encrypted', self.codes())


if __name__ == '__main__':
    unittest.main()
