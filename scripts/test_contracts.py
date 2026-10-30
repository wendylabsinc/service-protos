"""Adversarial tests use real Buf and independently built before/after graphs."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('contracts', Path(__file__).with_name('contracts.py'))
contracts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contracts)
ROOT = contracts.ROOT


class CompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.views = contracts.manifest(ROOT)
        cls.provenance = contracts.read_json(ROOT / 'contracts/baselines/provenance.json')
        (ROOT / '.contract-work').mkdir(exist_ok=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.contract-work')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def image(self, name, schema):
        directory = self.work / name
        directory.mkdir()
        (directory / 'test.proto').write_text(schema)
        (directory / 'buf.yaml').write_text(json.dumps(contracts.STRICT))
        image = self.work / (name + '.binpb')
        contracts.buf('build', directory, '-o', image)
        return image

    def assert_breaks(self, before, after, rule):
        old = self.image('old', before)
        new = self.image('new', after)
        with self.assertRaisesRegex(ValueError, rule):
            contracts.compare(new, old)

    def test_changed_request_type_fails(self):
        schema = '''syntax = "proto3"; package test.v1;
message Request {} message Replacement {} message Response {}
service ExampleService { rpc Call(Request) returns (Response); }
'''
        self.assert_breaks(schema, schema.replace('Call(Request)', 'Call(Replacement)'), 'request type')

    def test_removed_enum_value_fails(self):
        schema = '''syntax = "proto3"; package test.v1;
enum State { STATE_UNSPECIFIED = 0; STATE_READY = 1; }
'''
        self.assert_breaks(schema, schema.replace('STATE_READY = 1;', ''), 'enum value')

    def copy_catalogue(self):
        dest = self.work / 'repo'
        shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns('.git', '.contract-work', '__pycache__'))
        return dest

    def test_stable_tag_selection_uses_numeric_versions(self):
        with patch.object(contracts, 'run', return_value='v1.9.0\nv1.10.0\nv2.0.0-rc.1\nother\nv1.0.0\n'):
            self.assertEqual(contracts.stable_tags(), ['v1.0.0', 'v1.9.0', 'v1.10.0'])

    def test_independent_previous_graph_catches_later_deletion(self):
        # The initial migration image cannot know a field added in a later release.
        initial = 'syntax = "proto3"; package test.v1; message Request { string id = 1; }'
        released = initial.replace('string id = 1;', 'string id = 1; string later = 2;')
        old = self.image('migration', initial)
        stable = self.image('stable', released)
        candidate = self.image('candidate', initial)
        contracts.compare(candidate, old)
        with self.assertRaisesRegex(ValueError, 'field'):
            contracts.compare(candidate, stable)

    def test_candidate_cannot_be_its_own_baseline(self):
        with self.assertRaisesRegex(ValueError, 'candidate itself'):
            contracts.check('HEAD')

    def test_generation_selection_cannot_hide_a_file(self):
        changed = copy.deepcopy(self.views)
        changed['cloud-main-local']['roots'].remove('org_invites.proto')
        with self.assertRaisesRegex(ValueError, 'generation roots'):
            contracts.verify_sources(ROOT, changed, self.provenance)

    def test_catalogue_cannot_remap_deleted_root(self):
        changed = copy.deepcopy(self.views)
        changed['catalogue']['files']['org_invites.proto'] = changed['cloud-main-local']['files']['org_invites.proto']
        with self.assertRaisesRegex(ValueError, 'repository root'):
            contracts.verify_sources(ROOT, changed, self.provenance)

    def test_deleted_view_cannot_hide(self):
        changed = copy.deepcopy(self.views)
        del changed['cloud-main-local']
        with self.assertRaisesRegex(ValueError, 'view selection'):
            contracts.verify_sources(ROOT, changed, self.provenance)

    def test_deleted_graph_file_cannot_hide(self):
        changed = copy.deepcopy(self.views)
        del changed['cloud-main-local']['files']['org_invites.proto']
        with self.assertRaisesRegex(ValueError, 'removed import path|generation roots'):
            contracts.verify_sources(ROOT, changed, self.provenance)

    def test_source_drift_fails(self):
        dest = self.copy_catalogue()
        source = dest / self.views['cloud-main-local']['files']['org_invites.proto']
        source.write_bytes(source.read_bytes() + b'\n// accidental drift\n')
        with self.assertRaisesRegex(ValueError, 'source drift'):
            contracts.verify_sources(dest, self.views, self.provenance)

    def evolve_canonical(self, remap=True):
        dest = self.copy_catalogue()
        views = copy.deepcopy(self.views)
        source = dest / 'users.proto'
        preserved = contracts.source_audit.preserved_source('users.proto')
        captured = dest / preserved
        captured.parent.mkdir(parents=True)
        captured.write_bytes(source.read_bytes())
        source.write_text(source.read_text().replace(
            'message GetUserRequest {', 'message GetUserRequest {\n  optional string etag = 2;'))
        if remap:
            for name, view in views.items():
                if name != 'catalogue':
                    for path, selected in view['files'].items():
                        if selected == 'users.proto':
                            view['files'][path] = preserved
        return dest, views

    def test_additive_canonical_edit_preserves_frozen_views(self):
        dest, views = self.evolve_canonical()
        contracts.verify_sources(dest, views, self.provenance)
        # The real checker still builds/lints the evolved root and requires
        # strict FILE compatibility. Frozen clients retain identical images.
        before = contracts.build(ROOT, 'before', self.views['catalogue'], self.work)
        after = contracts.build(dest, 'after', views['catalogue'], self.work, lint=True)
        contracts.compare(after, before)
        for name, view in views.items():
            if name != 'catalogue':
                image = contracts.build(dest, name, view, self.work)
                self.assertEqual(contracts.digest(image), self.provenance['views'][name]['descriptor_sha256'])

    def test_canonical_edit_requires_preserved_history(self):
        dest, views = self.evolve_canonical()
        (dest / contracts.source_audit.preserved_source('users.proto')).unlink()
        with self.assertRaisesRegex(ValueError, 'source drift'):
            contracts.verify_sources(dest, views, self.provenance)

    def test_frozen_view_must_select_preserved_bytes(self):
        dest, views = self.evolve_canonical(remap=False)
        with self.assertRaisesRegex(ValueError, 'source drift at users.proto'):
            contracts.verify_sources(dest, views, self.provenance)

    def test_preserved_source_cannot_forge_history(self):
        dest, views = self.evolve_canonical()
        captured = dest / contracts.source_audit.preserved_source('users.proto')
        captured.write_bytes(captured.read_bytes() + b'// forged history\n')
        with self.assertRaisesRegex(ValueError, 'preserved source drift'):
            contracts.verify_sources(dest, views, self.provenance)

    def test_inventory_rewrite_fails(self):
        dest = self.copy_catalogue()
        inventory = dest / 'contracts/inventory.json'
        inventory.write_bytes(inventory.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'inventory is immutable'):
            contracts.verify_sources(dest, self.views, self.provenance)

    def test_config_exemption_fails(self):
        dest = self.copy_catalogue()
        config = contracts.read_json(dest / 'buf.yaml')
        config['breaking']['except'] = ['RPC_SAME_REQUEST_TYPE']
        (dest / 'buf.yaml').write_text(json.dumps(config))
        with self.assertRaisesRegex(ValueError, 'configuration differs'):
            contracts.verify_sources(dest, self.views, self.provenance)

    def test_config_module_exclusion_fails(self):
        dest = self.copy_catalogue()
        config = contracts.read_json(dest / 'buf.yaml')
        config['modules'][0]['excludes'].append('wendycloud')
        (dest / 'buf.yaml').write_text(json.dumps(config))
        with self.assertRaisesRegex(ValueError, 'configuration differs'):
            contracts.verify_sources(dest, self.views, self.provenance)

    def test_unlisted_source_fails(self):
        dest = self.copy_catalogue()
        (dest / 'untracked.proto').write_text('syntax = "proto3";')
        with self.assertRaisesRegex(ValueError, 'unmanifested'):
            contracts.verify_sources(dest, self.views, self.provenance)

    def test_conformance_fixture_drift_fails(self):
        dest = self.copy_catalogue()
        source = dest / 'conformance/reqsig/signed-request-vectors-v1.json'
        source.write_bytes(source.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'fixture drift'):
            contracts.verify_sources(dest, self.views, self.provenance)

    def test_baseline_descriptor_drift_fails(self):
        dest = self.copy_catalogue()
        (dest / 'contracts/baselines/cloud-main-local.binpb').write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'descriptor drift'):
            contracts.verify_sources(dest, self.views, self.provenance)

    def test_signed_method_option_change_fails(self):
        before = contracts.build(ROOT, 'before', self.views['catalogue'], self.work)
        module = self.work / 'before'
        proto = module / 'wendycloud/v2/apps.proto'
        proto.write_text(proto.read_text().replace('option (wendy.signed_request) = true;', '', 1))
        after = self.work / 'after.binpb'
        contracts.buf('build', module, '-o', after)
        with self.assertRaisesRegex(ValueError, 'signed-request contract'):
            contracts.compare(after, before)

    def test_additive_field_passes(self):
        schema = 'syntax = "proto3"; package test.v1; message Request { string id = 1; }'
        before = self.image('old', schema)
        after = self.image('new', schema.replace('string id = 1;', 'string id = 1; optional string name = 2;'))
        contracts.compare(after, before)

    def test_materialized_graph_matches_capture_exactly(self):
        for name, view in self.views.items():
            with self.subTest(view=name):
                image = contracts.build(ROOT, name, view, self.work)
                if name == 'catalogue':
                    contracts.compare(image, ROOT / 'contracts/baselines/catalogue.binpb')
                else:
                    self.assertEqual(contracts.digest(image), self.provenance['views'][name]['descriptor_sha256'])


if __name__ == '__main__':
    unittest.main()
