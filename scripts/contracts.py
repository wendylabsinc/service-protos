#!/usr/bin/env python3
"""Build every catalogue view and compare independently captured contract graphs."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BUF_VERSION = '1.75.0'
STRICT = {'version': 'v2', 'breaking': {'use': ['FILE']}}
spec = importlib.util.spec_from_file_location('provenance', ROOT / 'scripts/verify-provenance.py')
source_audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source_audit)


def run(*args, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if result.returncode:
        raise ValueError(f'{args[0]} {args[1]} failed:\n{result.stdout}{result.stderr}')
    return result.stdout


def buf(*args):
    return run(os.environ.get('BUF', 'buf'), *map(str, args))


def read_json(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_path(root, name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name or not name:
        raise ValueError(f'unsafe contract path: {name}')
    target = root / name
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError(f'contract path escapes catalogue: {name}')
    return target


def manifest(root):
    data = read_json(root / 'contracts/views.json')
    if data['version'] != 1 or not data['views']:
        raise ValueError('unsupported or empty view manifest')
    return data['views']


def config(view):
    return {**STRICT, 'modules': [{'path': '.'}], 'lint': view['lint']}


def materialize(root, view, output):
    if output.exists():
        raise ValueError(f'output already exists: {output}')
    output.mkdir(parents=True)
    for path, source in view['files'].items():
        target = safe_path(output, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(safe_path(root, source), target)
    (output / 'buf.yaml').write_text(json.dumps(config(view), indent=2) + '\n')


def verify_sources(root, views, provenance, first_migration=False):
    inventory = read_json(root / 'contracts/inventory.json')
    if digest(root / 'contracts/inventory.json') != provenance['inventory_sha256']:
        raise ValueError('captured source inventory is immutable')
    source_audit.verify(root, inventory)
    expected = provenance['views']
    if set(views) != set(expected) or set(views) != set(inventory['graphs']):
        raise ValueError('view selection differs from captured migration graphs')
    covered = set()
    for name, view in views.items():
        original = inventory['graphs'][name]
        if not set(expected[name]['roots']) <= set(view['roots']) or not set(view['roots']) <= set(view['files']):
            raise ValueError(f'{name}: generation roots removed or missing')
        if name != 'catalogue' and view['roots'] != expected[name]['roots']:
            raise ValueError(f'{name}: frozen generation roots changed')
        if view['lint'] != expected[name]['lint']:
            raise ValueError(f'{name}: naming lint allowances changed')
        if name == 'catalogue' and any(p != source for p, source in view['files'].items()):
            raise ValueError('catalogue import paths must remain at the repository root')
        if not set(original) <= set(view['files']):
            raise ValueError(f'{name}: removed import path from migration graph')
        # Published compatibility views are frozen. The root catalogue is additive.
        if name != 'catalogue' and set(original) != set(view['files']):
            raise ValueError(f'{name}: frozen graph selection changed')
        for path, source in view['files'].items():
            file = safe_path(root, source)
            if file.suffix != '.proto' or file.is_symlink() or not file.is_file():
                raise ValueError(f'{name}: source must be a regular .proto file: {source}')
            covered.add(source)
            if path in original and (name != 'catalogue' or first_migration):
                recorded = original[path]
                allowed = {recorded}
                if not recorded.startswith('contracts/'):
                    allowed.add(source_audit.preserved_source(recorded))
                if source not in allowed or digest(file) != inventory['sources'][recorded]['sha256']:
                    raise ValueError(f'{name}: source drift at {path}')
    actual = {str(p.relative_to(root)).replace('\\', '/') for p in root.rglob('*.proto')
              if '.git' not in p.relative_to(root).parts and '.contract-work' not in p.relative_to(root).parts}
    # Copies retained for the historical audit can outlive a view's need for
    # them. The source auditor has already checked their deterministic paths
    # and original hashes; arbitrary additional proto copies still fail.
    covered.update(p for p in actual if p.startswith(source_audit.CAPTURED))
    if actual != covered:
        raise ValueError(f'unmanifested/missing sources: {sorted(actual ^ covered)}')
    # Root consumers keep their original graph. No new root exclusions or rule bypasses.
    wanted = config(views['catalogue'])
    wanted['modules'][0]['excludes'] = ['contracts', '.contract-work']
    if read_json(root / 'buf.yaml') != wanted:
        raise ValueError('root Buf configuration differs from strict catalogue configuration')
    for name, entry in expected.items():
        if digest(root / f'contracts/baselines/{name}.binpb') != entry['descriptor_sha256']:
            raise ValueError(f'{name}: captured descriptor drift')
    for path, checksum in provenance.get('fixtures', {}).items():
        if digest(safe_path(root, path)) != checksum:
            raise ValueError(f'conformance fixture drift: {path}')


def snapshot(ref, output):
    # Only object IDs or refs resolved by Git reach archive. Never execute baseline code.
    oid = run('git', 'rev-parse', '--verify', ref + '^{commit}', cwd=ROOT).strip()
    data = subprocess.check_output(['git', 'archive', oid], cwd=ROOT)
    output.mkdir()
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        archive.extractall(output, filter='data')
    return output


def build(root, name, view, work, lint=False):
    module = work / name
    materialize(root, view, module)
    image = work / (name + '.binpb')
    paths = [arg for root in view['roots'] for arg in ('--path', module / root)]
    buf('build', module, '--exclude-source-info', '-o', image, *paths)
    if lint:
        buf('lint', module)
    return image


def compare(candidate, previous):
    # Supply policy ourselves. A baseline's relaxed buf.yaml cannot weaken this check.
    buf('breaking', candidate, '--against', previous, '--config', json.dumps(STRICT))
    def signed_methods(image):
        graph = json.loads(buf('build', image, '--exclude-source-info', '-o', '-#format=json'))
        return {f"{file.get('package', '')}.{service['name']}/{method['name']}":
                method.get('options', {}).get('[wendy.signed_request]', False)
                for file in graph['file'] for service in file.get('service', [])
                for method in service.get('method', [])}
    old, new = signed_methods(previous), signed_methods(candidate)
    for method, signed in old.items():
        if method not in new or new[method] != signed:
            raise ValueError(f'signed-request contract changed: {method}')


def stable_tags():
    tags = run('git', 'tag', '--list', cwd=ROOT).splitlines()
    versions = [(tuple(map(int, t[1:].split('.'))), t) for t in tags
                if re.fullmatch(r'v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', t)]
    return [t for _, t in sorted(versions)]


def check(base):
    if buf('--version').strip() != BUF_VERSION:
        raise ValueError(f'Buf {BUF_VERSION} required')
    if run('git', 'rev-parse', '--is-shallow-repository', cwd=ROOT).strip() != 'false':
        raise ValueError('full history and tags are required for stable baseline selection')
    if run('git', 'rev-parse', base + '^{commit}', cwd=ROOT).strip() == run('git', 'rev-parse', 'HEAD', cwd=ROOT).strip():
        raise ValueError('PR base must not be the candidate itself')
    views = manifest(ROOT)
    provenance = read_json(ROOT / 'contracts/baselines/provenance.json')
    work_root = ROOT / '.contract-work'
    work_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work_root) as tmp:
        work = Path(tmp)
        base_root = snapshot(base, work / 'base')
        initial = not (base_root / 'contracts/views.json').exists()
        if initial:
            # Piece 1 is the independent import authority, even though its
            # forward-only history contains an earlier all-in-one prototype.
            inventory = base_root / 'contracts/inventory.json'
            if not inventory.is_file() or digest(inventory) != provenance['inventory_sha256']:
                raise ValueError('pre-view PR base differs from captured source inventory')
            if read_json(inventory)['captured_catalogue_commit'] != provenance['catalogue_base']:
                raise ValueError('captured catalogue origin differs from source inventory')
        else:
            trusted = read_json(base_root / 'contracts/baselines/provenance.json')
            if provenance != trusted:
                raise ValueError('migration provenance is immutable')
        verify_sources(ROOT, views, provenance, initial)
        candidate = work / 'candidate'
        candidate.mkdir()
        images = {name: build(ROOT, name, view, candidate, lint=True) for name, view in views.items()}
        # Always check first-release graphs. There is no "no tag yet" skip.
        for name, image in images.items():
            compare(image, ROOT / f'contracts/baselines/{name}.binpb')
        references = [('PR base', base_root)]
        tags = stable_tags()
        if tags:
            references.append((tags[-1], snapshot(tags[-1], work / 'stable')))
        else:
            print('Stable baseline: captured pre-migration descriptors (no stable tag yet)')
        for index, (label, previous_root) in enumerate(references):
            old_manifest = previous_root / 'contracts/views.json'
            if old_manifest.exists():
                previous = manifest(previous_root)
                if not set(previous) <= set(views):
                    raise ValueError(f'{label}: candidate deleted a compatibility view')
                outputs = work / f'previous-{index}'
                outputs.mkdir()
                for name, view in previous.items():
                    compare(images[name], build(previous_root, name, view, outputs))
            else:
                old_image = work / 'original-master.binpb'
                buf('build', previous_root, '--exclude-source-info', '-o', old_image)
                compare(images['catalogue'], old_image)
            print(f'PASS: strict FILE against {label}')
        print(f'PASS: build, lint, provenance and migration baselines for {len(views)} views')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    check_parser = commands.add_parser('check')
    check_parser.add_argument('--base', required=True, help='PR base SHA, not candidate HEAD')
    export_parser = commands.add_parser('export')
    export_parser.add_argument('view')
    export_parser.add_argument('output', type=Path)
    image_parser = commands.add_parser('image')
    image_parser.add_argument('view')
    image_parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if args.command == 'check':
        check(args.base)
    elif args.command == 'export':
        materialize(ROOT, manifest(ROOT)[args.view], args.output)
    else:
        if buf('--version').strip() != BUF_VERSION:
            raise ValueError(f'Buf {BUF_VERSION} required')
        work_root = ROOT / '.contract-work'
        work_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work_root) as temp:
            image = build(ROOT, args.view, manifest(ROOT)[args.view], Path(temp))
            shutil.copyfile(image, args.output)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, FileNotFoundError) as error:
        raise SystemExit(str(error))
