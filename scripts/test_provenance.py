"""Exercise inventory failures without network, Buf, or future catalogue machinery."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('provenance', Path(__file__).with_name('verify-provenance.py'))
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.name = 'contracts/sources/example/test.proto'
        self.source = self.root / self.name
        self.source.parent.mkdir(parents=True)
        self.data = b'syntax = "proto3";\npackage example.v1;\n'
        self.source.write_bytes(self.data)
        self.blob = hashlib.sha1(b'blob ' + str(len(self.data)).encode() + b'\0' + self.data).hexdigest()
        self.inventory = {
            'version': 1,
            'graphs': {'example': {'test.proto': self.name}},
            'sources': {self.name: {
                'sha256': hashlib.sha256(self.data).hexdigest(),
                'origins': [{'repository': 'example', 'commit': 'a' * 40, 'path': 'test.proto', 'blob': self.blob}],
            }},
        }

    def test_unchanged_source_passes(self):
        self.assertEqual(provenance.verify(self.root, self.inventory), (1, 1))

    def test_source_drift_fails(self):
        self.source.write_bytes(self.data + b'// changed\n')
        with self.assertRaisesRegex(ValueError, 'source drift'):
            provenance.verify(self.root, self.inventory)

    def test_missing_source_fails(self):
        self.source.unlink()
        with self.assertRaisesRegex(ValueError, 'file inventory differs'):
            provenance.verify(self.root, self.inventory)

    def test_unrecorded_import_fails(self):
        self.source.with_name('extra.proto').write_bytes(self.data)
        with self.assertRaisesRegex(ValueError, 'file inventory differs'):
            provenance.verify(self.root, self.inventory)

    def test_dangling_graph_reference_fails(self):
        self.inventory['graphs']['example']['missing.proto'] = 'missing.proto'
        with self.assertRaisesRegex(ValueError, 'missing or unreferenced'):
            provenance.verify(self.root, self.inventory)

    def test_changed_hash_does_not_forge_original_blob(self):
        self.source.write_bytes(self.data + b'// changed\n')
        self.inventory['sources'][self.name]['sha256'] = hashlib.sha256(self.source.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'Git blob mismatch'):
            provenance.verify(self.root, self.inventory)

    def test_upstream_mismatch_fails(self):
        tree = {'test.proto': {'type': 'blob', 'mode': '100644', 'sha': 'b' * 40}}
        with patch.object(provenance, 'upstream_tree', return_value=tree):
            with self.assertRaisesRegex(ValueError, 'upstream source mismatch'):
                provenance.verify(self.root, self.inventory, upstream=True)

    def test_mutable_or_abbreviated_upstream_revision_fails(self):
        for revision in ('master', 'v1.0.0', 'a' * 7, 'g' * 40):
            with self.subTest(revision=revision):
                self.inventory['sources'][self.name]['origins'][0]['commit'] = revision
                with self.assertRaisesRegex(ValueError, 'full immutable commit'):
                    provenance.verify(self.root, self.inventory)

    def test_outside_source_refused(self):
        with self.assertRaisesRegex(ValueError, 'invalid source path'):
            provenance.source_path(self.root, '../outside.proto')


if __name__ == '__main__':
    unittest.main()
