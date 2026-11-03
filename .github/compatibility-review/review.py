"""One bounded, tool-free model call. Git objects are data, never executed."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

HERE = Path(__file__).parent
MAX_CONTEXT = 120_000
MAX_FILE = 16_000


def source(path):
    # This repo has no existing AI filter. GRPCGenerated.swift is generated output.
    # Keep generated code out by selecting source formats, before reading blobs.
    return (path.endswith(('.proto', '.md')) or path in {
        'buf.yaml', 'grpc-swift-proto-generator-config.json'
    } or (path.startswith('conformance/') and path.endswith(('/generate.go', '/verify.go')))
        or (path.startswith('.github/') and path.endswith(('.py', '.cjs', '.yml', '.yaml'))))


def git(*args):
    return subprocess.check_output(['git', *args])


def context(base, head):
    for sha in (base, head):
        if not re.fullmatch('[0-9a-f]{40}', sha):
            raise ValueError('Invalid revision')
    ancestor = git('merge-base', base, head).decode().strip()
    changed = git('diff', '--no-renames', '--name-only', '-z', ancestor, head).decode().split('\0')[:-1]
    if len(changed) > 100:
        raise ValueError('More than 100 changed paths: bounded review unavailable')
    trees = {}
    for side, sha in (('before', ancestor), ('after', head)):
        trees[side] = {}
        for entry in git('ls-tree', '-r', '-z', sha).split(b'\0'):
            if entry:
                metadata, path = entry.split(b'\t', 1)
                mode, kind, oid = metadata.decode().split()
                trees[side][path.decode()] = (mode, kind, oid)
    files, omitted, used = [], [], 0

    def add(path, side, unchanged=False):
        nonlocal used
        entry = trees[side].get(path)
        if not entry:
            return
        mode, kind, oid = entry
        if not source(path) or mode != '100644' or kind != 'blob':
            omitted.append(f'{side}:{path} (outside source formats or nonregular)')
            return
        size = int(git('cat-file', '-s', oid))
        if size > MAX_FILE or used + size > MAX_CONTEXT:
            omitted.append(f'{side}:{path} (context limit)')
            return
        raw = git('cat-file', 'blob', oid)
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            omitted.append(f'{side}:{path} (non-UTF8)')
            return
        if '\0' in text:
            omitted.append(f'{side}:{path} (binary)')
            return
        files.append(dict(id=len(files) + 1, path=path, side=side,
                          unchanged=unchanged, text=text))
        used += size

    for path in changed:
        for side in trees:
            add(path, side)
    # A small relevant neighborhood. Include versioned siblings if in the same dir.
    parents = {str(Path(p).parent) for p in changed if p.endswith('.proto')}
    for path in sorted(trees['after']):
        if path not in changed and path.endswith('.proto') and str(Path(path).parent) in parents:
            add(path, 'after', True)
    return dict(base=base, head=head, merge_base=ancestor, changed=changed,
                files=files, omitted=omitted,
                limitation='Only selected source and nearby schemas. No released consumer or deployment verification.')


def validate(result, ctx):
    if not isinstance(result, dict) or set(result) != {'findings', 'gaps'}:
        raise ValueError('Invalid review response')
    if not isinstance(result['findings'], list) or len(result['findings']) > 6:
        raise ValueError('Invalid findings')
    if not isinstance(result['gaps'], list) or len(result['gaps']) > 8:
        raise ValueError('Invalid gaps')
    catalog = {f['id']: f for f in ctx['files']}
    def short(text):
        return isinstance(text, str) and 0 < len(text.strip()) <= 1000
    if not all(short(g) for g in result['gaps']):
        raise ValueError('Invalid gap text')
    for f in result['findings']:
        if not isinstance(f, dict) or set(f) != {'direction', 'affected', 'action', 'failure', 'evidence', 'suggestion'}:
            raise ValueError('Invalid finding fields')
        if f['direction'] not in {'older-client', 'newer-client'} or not all(short(f[k]) for k in ('affected', 'action', 'failure', 'suggestion')):
            raise ValueError('Missing affected consumer, action or failure')
        if not f['suggestion'].startswith('Consider ') or f['suggestion'].count('Consider ') != 1:
            raise ValueError('Missing Consider suggestion')
        if not isinstance(f['evidence'], list) or not 1 <= len(f['evidence']) <= 4:
            raise ValueError('Missing evidence')
        changed_evidence = False
        for e in f['evidence']:
            if not isinstance(e, dict) or set(e) != {'id', 'quote'} or type(e['id']) is not int:
                raise ValueError('Invalid evidence reference')
            item = catalog.get(e['id'])
            if not item or not short(e['quote']) or e['quote'] not in item['text']:
                raise ValueError('Evidence is not in supplied source')
            changed_evidence |= not item['unchanged']
        if not changed_evidence:
            raise ValueError('Finding has no changed-file evidence')
    return result


def model(ctx, key):
    payload = dict(model='claude-sonnet-5-5', max_tokens=3000,
                   system=(HERE / 'guidance.md').read_text(),
                   messages=[dict(role='user', content=json.dumps(ctx))])
    request = urllib.request.Request('https://api.anthropic.com/v1/messages',
        data=json.dumps(payload).encode(), headers={'x-api-key': key,
        'anthropic-version': '2023-06-01', 'content-type': 'application/json'})
    with urllib.request.urlopen(request, timeout=180) as response:
        data = json.load(response)
    # Provider usage only. No price table or paid retries/benchmarks.
    print('Provider usage: ' + json.dumps(data.get('usage', {})), file=sys.stderr)
    if data.get('stop_reason') != 'end_turn':
        raise ValueError('Model response incomplete')
    return validate(json.loads(''.join(b['text'] for b in data['content'] if b['type'] == 'text')), ctx)


def render(result, ctx):
    # Quote all model text so @mentions/HTML cannot notify or impersonate prose.
    def literal(text):
        return '<pre>' + __import__('html').escape(text).replace('@', '&#64;') + '</pre>'
    lines = ['<!-- automated-compatibility-review -->', '### Automated Compatibility Review — advisory',
             f"Head `{ctx['head']}`, base `{ctx['base']}`, merge base `{ctx['merge_base']}`.",
             'Coverage is incomplete. No release/deployment verification was performed. Buf remains a separate structural check.',
             f"Source snapshots: {len(ctx['files'])}. Omitted snapshots: {len(ctx['omitted'])}."]
    for f in result['findings']:
        lines += [literal(f"{f['direction']}: {f['affected']}\n{f['action']} → {f['failure']}\n{f['suggestion']}")]
        for e in f['evidence']:
            item = next(v for v in ctx['files'] if v['id'] == e['id'])
            line = item['text'][:item['text'].index(e['quote'])].count('\n') + 1
            lines += [literal(f"{item['side']} {item['path']}:{line}\n{e['quote']}")]
    if not result['findings']:
        lines += ['No evidence-backed findings in supplied context. This does not establish compatibility or resolve earlier findings.']
    lines += ['Insufficient evidence:'] + [literal(g) for g in result['gaps']]
    lines += [literal(o) for o in ctx['omitted']]
    report = '\n\n'.join(lines)
    if len(report.encode()) > 50_000:
        raise ValueError('Report exceeds publication limit')
    return report


def main():
    failed = False
    try:
        ctx = context(os.environ['BASE_SHA'], os.environ['HEAD_SHA'])
        key = os.environ.get('ANTHROPIC_API_KEY')
        if not key:
            raise ValueError('Setup required: ANTHROPIC_API_KEY is not configured for this repository')
        if not ctx['files']:
            raise ValueError('No reviewable source snapshots were supplied')
        report = render(model(ctx, key), ctx)
    except Exception as error:
        # Do not expose provider errors, response content or credential-bearing URLs.
        reason = str(error) if isinstance(error, ValueError) else type(error).__name__
        report = ('<!-- automated-compatibility-review -->\n### Automated Compatibility Review — unavailable\n'
                  'No compatibility conclusion was reached. Earlier findings remain unresolved.\n' + reason)
        failed = True
    Path(os.environ['GITHUB_STEP_SUMMARY']).write_text(report)
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        # JSON escapes newlines, so source/model text cannot inject output records.
        output.write('report=' + json.dumps(report) + '\n')
    return int(failed)


if __name__ == '__main__':
    sys.exit(main())
