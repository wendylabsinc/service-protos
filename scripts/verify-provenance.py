#!/usr/bin/env python3
"""Verify the imported byte inventory, optionally against immutable GitHub trees."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def source_path(root, name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name or path.suffix != '.proto':
        raise ValueError(f'invalid source path: {name}')
    source = root / name
    if source.is_symlink() or not source.resolve().is_relative_to(root.resolve()):
        raise ValueError(f'source must be an in-repository regular file: {name}')
    return source


def upstream_tree(repository, commit):
    response = json.loads(subprocess.check_output([
        'gh', 'api', f'repos/wendylabsinc/{repository}/git/trees/{commit}?recursive=1']))
    if response.get('truncated'):
        raise ValueError(f'cannot audit truncated tree: {repository}@{commit}')
    return {item['path']: item for item in response['tree']}


def verify(root, inventory, upstream=False):
    if inventory['version'] != 1 or not inventory['sources'] or not inventory['graphs']:
        raise ValueError('unsupported or empty inventory')
    sources = inventory['sources']
    referenced = {source for graph in inventory['graphs'].values() for source in graph.values()}
    if referenced != set(sources):
        raise ValueError('graph inventory has missing or unreferenced sources')
    imported = {p.relative_to(root).as_posix() for p in (root / 'contracts/sources').rglob('*.proto')}
    recorded = {path for path in sources if path.startswith('contracts/sources/')}
    if imported != recorded:
        raise ValueError(f'imported file inventory differs: {sorted(imported ^ recorded)}')
    trees = {}
    origin_count = 0
    for name, record in sources.items():
        data = source_path(root, name).read_bytes()
        if hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError(f'source drift: {name}')
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if not record['origins']:
            raise ValueError(f'no provenance: {name}')
        for origin in record['origins']:
            if blob != origin['blob']:
                raise ValueError(f'Git blob mismatch: {name}')
            if upstream:
                key = origin['repository'], origin['commit']
                if key not in trees:
                    trees[key] = upstream_tree(*key)
                    print(f'Fetched {key[0]}@{key[1]}', flush=True)
                item = trees[key][origin['path']]
                if item['type'] != 'blob' or item['mode'] not in ('100644', '100755') or item['sha'] != blob:
                    raise ValueError(f'upstream source mismatch: {name} at {key}')
            origin_count += 1
    return len(sources), origin_count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', action='store_true', help='requires gh read access to the recorded private repositories')
    args = parser.parse_args()
    inventory = json.loads((ROOT / 'contracts/inventory.json').read_text())
    sources, origins = verify(ROOT, inventory, args.upstream)
    print(f'PASS: {sources} source files, {origins} upstream file records' + (' verified against GitHub' if args.upstream else ' verified locally'))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
