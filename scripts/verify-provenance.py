#!/usr/bin/env python3
"""Read-only upstream audit. Requires gh authentication with all source repos readable."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
provenance = json.loads((ROOT / 'contracts/baselines/provenance.json').read_text())
views = json.loads((ROOT / 'contracts/views.json').read_text())['views']
trees = {}
count = 0
for view, graph in provenance['views'].items():
    for path, origin in graph['files'].items():
        key = origin['repository'], origin['commit']
        if key not in trees:
            repo, commit = key
            response = json.loads(subprocess.check_output([
                'gh', 'api', f'repos/wendylabsinc/{repo}/git/trees/{commit}?recursive=1']))
            if response.get('truncated'):
                raise SystemExit(f'Cannot audit truncated upstream tree: {repo}@{commit}')
            trees[key] = {item['path']: item for item in response['tree']}
            print(f'Fetched {repo}@{commit}', flush=True)
        item = trees[key][origin['path']]
        source = ROOT / views[view]['files'][path]
        data = source.read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if item['type'] != 'blob' or item['mode'] not in ('100644', '100755'):
            raise SystemExit(f'Not a source blob: {key} {origin["path"]}')
        if blob != item['sha'] or blob != origin['blob']:
            raise SystemExit(f'Upstream source drift: {view}/{path}')
        count += 1
print(f'PASS: {count} view sources match {len(trees)} immutable upstream trees')
