#!/usr/bin/env python3
"""Exercise the runner with real repository schemas, Git, Buf 1.75.0 and protoc 36.2.

python3 -m pip install -r tools/contracts-requirements.txt
python3 tools/test-contracts.py
Optional full-consumer probe: --consumer /scratch/consumer --source /repo/service-protos
Default controls copy real schemas and vectors from this checkout and use a
disposable Git graph without network access. Optional full-consumer probes copy
the prepared fixture and its fetched source history. Inputs stay untouched.
Run as an ordinary non-root user for real permission-failure coverage.
URL rewriting is scoped to child processes.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import yaml
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
URL = 'https://github.com/wendylabsinc/service-protos.git'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--consumer', type=Path, help='Optional full-consumer fixture')
parser.add_argument('--source', type=Path, default=HERE.parent)
parser.add_argument('--installation-child', type=Path, help=argparse.SUPPRESS)
args = parser.parse_args()
if os.geteuid() == 0:
    parser.error('permission controls require an ordinary non-root user')

if args.installation_child:
    spec = importlib.util.spec_from_file_location('contracts', HERE / 'contracts.py')
    child_runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(child_runner)
    outputs = {f'generated/output-{i:05}.pb.go': b'NEW output' for i in range(10000)}
    outputs['contracts.json'] = b'NEW pin'
    child_runner.install(args.installation_child, outputs, {'generated/output-00000.pb.go': b'original output'})
    raise SystemExit(0)


def git(*argv, cwd=None, env=None):
    return subprocess.check_output(['git', *argv], cwd=cwd, env=env, text=True).strip()


with tempfile.TemporaryDirectory(prefix='test-contracts-') as tmp:
    scratch = Path(tmp)
    source = scratch / 'source'
    consumer = scratch / 'consumer'
    if args.consumer:
        shutil.copytree(args.consumer, consumer, ignore=shutil.ignore_patterns('.git', '.build', 'Build'))
        cfg = json.loads((consumer / 'contracts.json').read_text())
        git('init', '-q', '--initial-branch=initial', str(source))
        git('fetch', '-q', str(args.source.resolve()), 'refs/remotes/origin/main:refs/heads/main', cfg['commit'], cwd=source)
        git('checkout', '-q', 'main', cwd=source)
    else:
        # Real schemas and vectors from this PR, real Git graph, real Buf and
        # protoc. No network, external consumer checkout or machine paths.
        git('init', '-q', '--initial-branch=main', str(source))
        entries = git('ls-files', cwd=args.source).splitlines()
        for rel in entries:
            if rel.endswith('.proto') or rel in ('buf.yaml', 'tools/check-pin.sh', 'conformance/set/set-vectors-v1.json'):
                dst = source / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(args.source / rel, dst)
        git('add', '.', cwd=source)
        git('-c', 'user.name=Contract test', '-c', 'user.email=contracts@example.invalid',
            '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
            'commit', '-q', '-m', 'Real source fixture', cwd=source)
        consumer.mkdir()
        cfg = {'commit': git('rev-parse', 'HEAD', cwd=source), 'paths': ['wendy/options.proto'],
               'outputs': [{'path': 'generated', 'patterns': ['*_pb2.py']}],
               'tools': [{'command': ['buf', '--version'], 'expect': '1.75.0'},
                         {'command': ['protoc', '--version'], 'expect': 'libprotoc 36.2'}],
               'repair': 'bash tools/contracts.sh generate'}
        (consumer / 'contracts.json').write_text(json.dumps(cfg, indent=2) + '\n')
        (consumer / 'buf.gen.yaml').write_text(
            '# Standard Buf YAML; compiler versions are checked separately.\n'
            'version: v2\nplugins:\n  - protoc_builtin: python\n    out: generated\n    strategy: all\n')
    git('init', '-q', str(consumer))
    original_pin = (consumer / 'contracts.json').read_bytes()
    original_template = (consumer / 'buf.gen.yaml').read_bytes()
    exception_file = consumer / 'contracts-exceptions.yaml'
    original_exceptions = exception_file.read_bytes() if exception_file.exists() else None
    git('config', 'user.name', 'Contract test', cwd=source)
    git('config', 'user.email', 'contracts@example.invalid', cwd=source)
    env = os.environ.copy()
    env['PATH'] = str(Path(sys.executable).parent) + os.pathsep + env['PATH']
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(scratch / 'gitconfig'),
               GIT_TERMINAL_PROMPT='0', CONTRACTS_RUNNER=str(HERE.parent))
    # Retain existing scoped CI credentials; append only this test's URL rewrite.
    count = int(env.get('GIT_CONFIG_COUNT', '0'))
    env[f'GIT_CONFIG_KEY_{count}'] = f'url.file://{source}.insteadOf'
    env[f'GIT_CONFIG_VALUE_{count}'] = URL
    env[f'GIT_CONFIG_KEY_{count + 1}'] = 'http.https://example.invalid/.extraheader'
    env[f'GIT_CONFIG_VALUE_{count + 1}'] = 'AUTHORIZATION: synthetic-contract-test'
    env['GIT_CONFIG_COUNT'] = str(count + 2)
    if not args.consumer:
        # Master gains a real-schema-derived identity after the consumer pin.
        # Keep generation pinned while testing policy against current main.
        policy_schema = source / 'policy_new.proto'
        policy_schema.write_bytes(b'// Master-only policy fixture.\n' +
            (source / 'authorization.proto').read_bytes().replace(
                b'package wendycloud.v1;', b'package contracts.runner.policy;', 1))
        git('add', policy_schema.name, cwd=source)
        git('-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
            'commit', '-q', '-m', 'Add main-only policy identity', cwd=source)
    git('checkout', '-q', '-b', 'branch-only', cfg['commit'], cwd=source)
    git('-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
        'commit', '-q', '--allow-empty', '-m', 'Unmerged control', cwd=source)
    branch_only = git('rev-parse', 'HEAD', cwd=source)
    git('checkout', '-q', 'main', cwd=source)
    cases = 0

    def write_config(value):
        (consumer / 'contracts.json').write_text(json.dumps(value, indent=2) + '\n')

    def snapshot():
        result = {'contracts.json': (consumer / 'contracts.json').read_bytes()}
        for out in cfg['outputs']:
            for path in (consumer / out['path']).rglob('*'):
                if path.is_file() and not path.is_symlink():
                    result[path.relative_to(consumer).as_posix()] = path.read_bytes()
        for dst in cfg.get('fixtures', {}).values():
            path = consumer / dst
            if path.is_file():
                result[dst] = path.read_bytes()
        return result

    def invoke(command, message='', extra=()):
        global cases
        before = snapshot()
        proc = subprocess.run(['bash', str(HERE / 'contracts.sh'), *command],
                              cwd=consumer, env=env, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
        assert 'synthetic-contract-test' not in proc.stdout, 'credential diagnostic leak'
        if message:
            assert proc.returncode != 0 and message in proc.stdout, proc.stdout
            assert cfg['repair'] in proc.stdout, proc.stdout
            assert snapshot() == before, 'failure mutated pin/output'
        else:
            assert proc.returncode == 0, proc.stdout
        cases += 1
        print(f'ok {cases}: {" ".join(command)} {message or "passes"}', flush=True)
        return proc.stdout

    if not args.consumer:
        invoke(['generate'])
    invoke(['check'])
    if not args.consumer:
        local = consumer / 'schemas/policy_new.proto'
        local.parent.mkdir()
        local.write_bytes((source / 'policy_new.proto').read_bytes())
        invoke(['check'], 'local shared schema copy or alias')
        local.unlink()
        renamed = consumer / 'schemas/renamed.proto'
        renamed.write_bytes((source / 'authorization.proto').read_bytes())
        invoke(['check'], 'local shared schema copy or alias')
        shared = (source / 'authorization.proto').read_bytes()
        renamed.write_bytes(b'// Local copy retained for client generation.\n' + shared)
        invoke(['check'], 'local shared schema copy or alias')
        renamed.write_bytes(b'/* Re-formatted local copy. */\n' + b'\n'.join(b'\t' + line + b'  ' for line in shared.split(b'\n')))
        invoke(['check'], 'local shared schema copy or alias')
        renamed.write_bytes(shared + b'\nmessage RunnerAddedLocalType { string value = 1; }\n')
        invoke(['check'], 'local shared schema copy or alias')
        annotations = (source / 'wendy/options.proto').read_bytes()
        renamed.write_bytes(annotations + b'\nmessage LocalOnlyAnnotationMarker { string note = 1; }\n')
        invoke(['check'], 'local shared schema copy or alias')
        # Real custom-option declarations with distinct qualified identities
        # remain valid local dependencies without introducing exceptions.
        vendor = annotations.replace(b'package wendy;', b'package contracts.runner.vendor;').replace(
            b'50001', b'51001').replace(b'50002', b'51002')
        renamed.write_bytes(vendor)
        subprocess.run(['buf', 'build', str(renamed), '--as-file-descriptor-set',
                        '-o', str(scratch / 'vendor-options.bin')], env=env, check=True)
        invoke(['check'])
        local_options = annotations.replace(b'signed_request', b'local_annotation').replace(
            b'50001', b'52001').replace(b'50002', b'52002')
        renamed.write_bytes(local_options)
        subprocess.run(['buf', 'build', str(renamed), '--as-file-descriptor-set',
                        '-o', str(scratch / 'local-options.bin')], env=env, check=True)
        invoke(['check'])
        renamed.unlink()
        reserved = consumer / 'proto/my_contract.proto'
        reserved.parent.mkdir()
        # Neither the filename nor raw bytes identify a catalogue schema.
        reserved.write_bytes(b'// Renamed local definition.\n' + (source / 'authorization.proto').read_bytes())
        invoke(['check'], 'local shared schema copy or alias')
        allowed = yaml.safe_load(original_exceptions) if original_exceptions else {}
        allowed['proto/my_contract.proto'] = 'Explicit reserved-root local-input control'
        exception_file.write_text(yaml.safe_dump(allowed))
        invoke(['check'])
        reserved.unlink()
        if original_exceptions is None:
            exception_file.unlink()
        else:
            exception_file.write_bytes(original_exceptions)
    if not args.consumer:
        # Version assertions read existing lock metadata rather than copying
        # its version into the contract manifest.
        lock = consumer / 'locked-tools.json'
        lock.write_text(json.dumps({'packages': {'node_modules/protoc': {'version': '36.2'}}}))
        lock_cfg = json.loads(json.dumps(cfg))
        lock_cfg['tools'][1] = {'command': ['protoc', '--version'], 'lockfile': lock.name,
                                'package': 'protoc', 'prefix': 'libprotoc '}
        write_config(lock_cfg)
        invoke(['check'])
        lock.write_text(json.dumps({'packages': {'node_modules/protoc': {'version': '0.0'}}}))
        invoke(['generate'], 'version mismatch')
        write_config(cfg)
        lock.unlink()
        platform_cfg = json.loads(json.dumps(cfg))
        expected_buf = platform_cfg['tools'][0].pop('expect')
        platform_cfg['tools'][0]['expect_by_platform'] = {'darwin': expected_buf, 'linux': expected_buf}
        write_config(platform_cfg)
        invoke(['check'])
        platform_cfg['tools'][0]['expect_by_platform'][sys.platform] = '0.0'
        write_config(platform_cfg)
        invoke(['generate'], 'version mismatch')
        platform_cfg['tools'][0]['expect'] = expected_buf
        write_config(platform_cfg)
        invoke(['generate'], 'exactly one version source')
        write_config(cfg)
        # A local generated input is explicit twice: an import declaration and
        # a literal exception. Reuse a real schema instead of a mock generator.
        local_input = consumer / 'local/authorization.proto'
        local_input.parent.mkdir()
        shutil.copyfile(source / 'authorization.proto', local_input)
        local_cfg = dict(cfg, imports={'local/authorization.proto': 'local_authorization.proto'},
                         plugin_paths=[[*cfg['paths'], 'local/authorization.proto']])
        write_config(local_cfg)
        invoke(['generate'], 'literal source exception')
        exception_file.write_text('local/authorization.proto: Explicit local-input control using the real schema.\n')
        invoke(['generate'])
        invoke(['check'])
        local_input.unlink()
        exception_file.unlink()
        write_config(cfg)
        invoke(['generate'])
        write_config(dict(cfg, compiler='protoc'))
        invoke(['generate'])
        invoke(['check'])
        write_config(cfg)
        invoke(['generate'])
        template = yaml.safe_load(original_template)
        subset_cfg = dict(cfg, paths=[*cfg['paths'], 'authorization.proto'],
                          plugin_paths=[cfg['paths'], ['authorization.proto']])
        template['plugins'].append(dict(template['plugins'][0]))
        (consumer / 'buf.gen.yaml').write_text(yaml.safe_dump(template))
        write_config(subset_cfg)
        invoke(['generate'])
        invoke(['check'])
        write_config(dict(subset_cfg, plugin_paths=[cfg['paths'], ['not-declared.proto']]))
        invoke(['generate'], 'declared input paths')
        write_config(dict(subset_cfg, plugin_paths=[cfg['paths'], cfg['paths']]))
        invoke(['generate'], 'conflicting plugin output')
        (consumer / 'buf.gen.yaml').write_bytes(original_template)
        write_config(cfg)
        invoke(['generate'])
    out = consumer / cfg['outputs'][0]['path']
    generated = next(p for p in out.rglob('*') if p.is_file() and p.name != 'Manual.swift')
    saved = generated.read_bytes()
    generated.unlink()
    invoke(['check'], 'missing:')
    generated.write_bytes(saved)
    generated.write_bytes(saved + b'\n// stale\n')
    invoke(['check'], 'changed:')
    generated.write_bytes(saved)
    extra = generated.with_name('extra_' + generated.name)
    extra.write_bytes(saved)
    invoke(['check'], 'extra:')
    manual = out / 'Manual.swift'
    manual.write_text('// handwritten\n')
    invoke(['generate'])
    assert not extra.exists() and manual.read_text() == '// handwritten\n'
    assert generated.stat().st_mode & 0o777 == 0o644
    preserve = generated.with_name('Preserved_' + generated.name)
    preserve.write_text('// preserved consumer-owned output\n')
    excluded = dict(cfg, outputs=[{**cfg['outputs'][0], 'exclude': [preserve.relative_to(out).as_posix()]}, *cfg['outputs'][1:]])
    write_config(excluded)
    invoke(['generate'])
    assert preserve.read_text() == '// preserved consumer-owned output\n'
    preserve.unlink()
    write_config(cfg)
    # Catalogue covers schemas not selected for this consumer, plus known aliases.
    for rel in ('local/authorization.proto', 'cloud/authorization.proto',
                'local/wendy/lite/sensorlink.proto'):
        local = consumer / rel
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text('syntax = "proto3";\n')
        invoke(['check'], 'local shared schema copy or alias:')
        local.unlink()
    ignored = consumer / 'Proto/cloud/authorization.proto'
    ignored.parent.mkdir(parents=True, exist_ok=True)
    ignored.write_text('syntax = "proto3";\n')
    ignore = consumer / '.gitignore'
    old_ignore = ignore.read_bytes() if ignore.exists() else b''
    ignore.write_bytes(old_ignore + b'\n/Proto/\n')
    invoke(['check'], 'local shared schema copy or alias:')
    ignored.unlink()
    ignore.write_bytes(old_ignore)
    git('update-index', '--add', '--cacheinfo', f'160000,{cfg["commit"]},clip-store/proto', cwd=consumer)
    invoke(['check'], 'local shared schema gitlink:')
    git('update-index', '--force-remove', 'clip-store/proto', cwd=consumer)
    ignored_import = consumer / '.ignored/custom.proto'
    ignored_import.parent.mkdir()
    shutil.copyfile(source / 'authorization.proto', ignored_import)
    ignore = consumer / '.gitignore'
    saved_ignore = ignore.read_bytes() if ignore.exists() else b''
    ignore.write_bytes(saved_ignore + b'\n/.ignored/\n')
    write_config(dict(cfg, imports={'.ignored/custom.proto': 'authorization.proto'}))
    invoke(['check'], 'local shared schema import needs exception')
    ignored_import.unlink()
    ignore.write_bytes(saved_ignore)
    write_config(cfg)
    local = consumer / 'local/authorization.proto'
    local.write_text('syntax = "proto3";\n')
    allowed = yaml.safe_load(original_exceptions) if original_exceptions else {}
    allowed['local/authorization.proto'] = 'Real local schema exception control'
    exception_file.write_text(yaml.safe_dump(allowed))
    invoke(['check'])
    local.unlink()
    if original_exceptions is None:
        exception_file.unlink()
    else:
        exception_file.write_bytes(original_exceptions)
    # The actual parser must reject duplicate entries rather than silently
    # replacing a reviewed exception reason. YAML options are unique too.
    local.write_bytes((source / 'authorization.proto').read_bytes())
    exception_file.write_text('local/authorization.proto: first reason\nlocal/authorization.proto: duplicate reason\n')
    invoke(['check', '--sources-only'], 'duplicate key')
    local.unlink()
    if original_exceptions is None:
        exception_file.unlink()
    else:
        exception_file.write_bytes(original_exceptions)
    (consumer / 'buf.gen.yaml').write_bytes(original_template + b'\nversion: v2\n')
    invoke(['generate'], 'duplicate key')
    (consumer / 'buf.gen.yaml').write_bytes(original_template)
    write_config(dict(cfg, fixtures={'conformance/set/set-vectors-v1.json': 'contracts-exceptions.yaml'}))
    invoke(['generate'], 'overlap configuration')
    write_config(cfg)
    # Fixtures are read at the schema pin and drift is part of the same comparison.
    fixture_cfg = dict(cfg, fixtures={'conformance/set/set-vectors-v1.json': 'test-fixtures/set.json'})
    write_config(fixture_cfg)
    invoke(['generate'])
    fixture = consumer / 'test-fixtures/set.json'
    assert fixture.read_bytes() == subprocess.check_output(
        ['git', '-C', str(source), 'show', f'{cfg["commit"]}:conformance/set/set-vectors-v1.json'])
    fixture.write_bytes(b'{}\n')
    invoke(['check'], 'changed: test-fixtures/set.json')
    invoke(['generate'])
    # The fixture path needs only Git and the runner, never Buf/protoc/plugins.
    minimal_bin = scratch / 'git-only-bin'
    minimal_bin.mkdir()
    for name in ('bash', 'git', 'mktemp', 'rm', 'dirname'):
        (minimal_bin / name).symlink_to(shutil.which(name))
    # Preserve the real interpreter's venv instead of relocating its symlink.
    (minimal_bin / 'python3').write_text('#!/bin/bash\nexec ' + shlex.quote(sys.executable) + ' "$@"\n')
    (minimal_bin / 'python3').chmod(0o755)
    full_path = env['PATH']
    expected_fixture = fixture.read_bytes()
    fixture.write_bytes(b'stale fixture')
    generated.write_bytes(saved + b'\n// preserve stale generated output\n')
    try:
        env['PATH'] = str(minimal_bin)
        assert shutil.which('buf', path=env['PATH']) is None
        assert shutil.which('protoc', path=env['PATH']) is None
        invoke(['generate', '--fixtures-only'])
        assert fixture.read_bytes() == expected_fixture
        assert generated.read_bytes() == saved + b'\n// preserve stale generated output\n'
        assert (consumer / 'contracts.json').read_bytes() == (json.dumps(fixture_cfg, indent=2) + '\n').encode()
        invoke(['check', '--sources-only'])
        (consumer / 'buf.gen.yaml').unlink()
        invoke(['check', '--pin-only'])
        (consumer / 'buf.gen.yaml').write_bytes(original_template)
    finally:
        env['PATH'] = full_path
        (consumer / 'buf.gen.yaml').write_bytes(original_template)
        generated.write_bytes(saved)
    write_config(cfg)
    fixture.unlink()
    bad_fixture = dict(cfg, fixtures={'conformance/absent.json': 'test-fixtures/set.json'})
    write_config(bad_fixture)
    invoke(['generate'], 'git failed')
    invoke(['bump', cfg['commit']], 'git failed')
    fixture.write_bytes(b'current fixture must survive')
    invoke(['generate', '--fixtures-only'], 'git failed')
    assert fixture.read_bytes() == b'current fixture must survive'
    fixture.unlink()
    write_config(cfg)
    invoke(['bump', branch_only], 'not an ancestor')
    changed_pin = dict(cfg, commit=branch_only)
    write_config(changed_pin)
    invoke(['check'], 'not an ancestor')
    copy = consumer / 'copied/renamed.proto'
    copy.parent.mkdir()
    copy.write_bytes((source / 'authorization.proto').read_bytes())
    generated.unlink()
    output = invoke(['check'], 'not an ancestor')
    assert 'sources: local shared schema copy or alias: copied/renamed.proto' in output
    assert 'missing: ' + generated.relative_to(consumer).as_posix() in output
    assert 'drift: shared generated output or fixtures drifted' in output
    invoke(['generate'], 'not an ancestor')
    invoke(['bump', branch_only], 'not an ancestor')
    try:
        env['PATH'] = str(minimal_bin)
        invoke(['check', '--sources-only'], 'local shared schema copy or alias')
        copy.unlink()
        invoke(['check', '--sources-only'])
        invoke(['check', '--pin-only'], 'not an ancestor')
    finally:
        env['PATH'] = full_path
        copy.unlink(missing_ok=True)
        generated.write_bytes(saved)
    write_config(cfg)
    bad = dict(cfg, paths=[*cfg['paths'], 'missing.proto'])
    write_config(bad)
    invoke(['generate'], 'selected schema missing from pin')
    invoke(['bump', cfg['commit']], 'selected schema missing from pin')
    write_config(cfg)
    template = yaml.safe_load(original_template)
    template['plugins'][0]['opt'] = ['InvalidOption=broken']
    (consumer / 'buf.gen.yaml').write_text(json.dumps(template))
    invoke(['generate'], 'buf failed')
    invoke(['bump', cfg['commit']], 'buf failed')
    (consumer / 'buf.gen.yaml').write_bytes(original_template)
    bad_tool = dict(cfg, tools=[*cfg['tools'], {'command': ['absent-contract-tool', '--version'], 'expect': '0'}])
    write_config(bad_tool)
    invoke(['generate'], 'required tool not found')
    write_config(cfg)
    generated.unlink()
    outside = scratch / 'outside'
    outside.write_bytes(saved)
    generated.symlink_to(outside)
    invoke(['generate'], 'unsafe symlink')
    assert outside.read_bytes() == saved
    generated.unlink()
    generated.write_bytes(saved)
    relocated = out.with_name(out.name + '-safe')
    out.rename(relocated)
    out.symlink_to(relocated, target_is_directory=True)
    invoke(['generate'], 'unsafe symlink')
    out.unlink()
    relocated.rename(out)
    unreadable = out / 'unreadable'
    unreadable.mkdir()
    unreadable.chmod(0)
    try:
        if os.geteuid() != 0:
            invoke(['generate'], 'Permission denied')
    finally:
        unreadable.chmod(0o700)
        unreadable.rmdir()
    bad_stage = dict(cfg, stage={cfg['paths'][0]: '../outside.proto'})
    write_config(bad_stage)
    # Config failures happen before generation and carry the same repair command.
    invoke(['generate'], 'unsafe relative path')
    write_config(dict(cfg, stage={cfg['paths'][0]: '.GIT/index'}))
    invoke(['generate'], 'unsafe relative path')
    write_config(cfg)
    if not args.consumer:
        # Only the current-main catalogue is unsafe; the older pin remains
        # valid. Policy acquisition must never fall back to the pinned catalogue,
        # while the independent pinned drift check still produces its signal.
        unsafe_schema = source / 'unsafe-policy.proto'
        unsafe_schema.symlink_to('authorization.proto')
        git('add', unsafe_schema.name, cwd=source)
        git('-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
            'commit', '-q', '-m', 'Unsafe current policy catalogue control', cwd=source)
        output = invoke(['check'], 'unsafe shared schema archive entry')
        assert 'generated output and fixtures check succeeded' in output
        invoke(['generate'], 'unsafe shared schema archive entry')
        unsafe_schema.unlink()
        git('add', '-u', cwd=source)
        git('-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
            'commit', '-q', '-m', 'Restore valid policy export', cwd=source)
    # All fetches fail through real Git, without a mock returning success.
    key = f'GIT_CONFIG_KEY_{count}'
    env[key] = f'url.file://{scratch / "unavailable"}.insteadOf'
    invoke(['generate'], 'git failed')
    invoke(['bump', cfg['commit']], 'git failed')
    write_config(fixture_cfg)
    fixture.write_bytes(b'fixture before network failure')
    invoke(['generate', '--fixtures-only'], 'git failed')
    assert fixture.read_bytes() == b'fixture before network failure'
    fixture.unlink()
    write_config(cfg)
    invoke(['check', '--sources-only'], 'git failed')
    invoke(['check', '--pin-only'], 'git failed')
    env[key] = f'url.file://{source}.insteadOf'
    invoke(['bump', cfg['commit']])
    invoke(['check'])
    # A real generated change on a merged side branch exercises pin-only drift
    # and successful installation of a different SHA, beyond a same-pin no-op.
    git('checkout', '-q', '-b', 'generation-change', cfg['commit'], cwd=source)
    schema = source / cfg['paths'][0]
    with schema.open('a') as stream:
        stream.write('\nmessage ContractsRunnerPinChange { string value = 1; }\n')
    git('add', cfg['paths'][0], cwd=source)
    git('-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
        'commit', '-q', '-m', 'Generated drift control in disposable source', cwd=source)
    candidate = git('rev-parse', 'HEAD', cwd=source)
    git('checkout', '-q', 'main', cwd=source)
    git('-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
        'merge', '-q', '--no-ff', '-s', 'ours', 'generation-change', '-m', 'Merge control', cwd=source)
    write_config(dict(cfg, commit=candidate))
    invoke(['check'], 'changed:')
    write_config(cfg)
    invoke(['bump', candidate])
    assert json.loads((consumer / 'contracts.json').read_text())['commit'] == candidate
    invoke(['check'])
    # A failing destination replacement must roll back earlier writes and pin.
    spec = importlib.util.spec_from_file_location('contracts', HERE / 'contracts.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    platform_tool = {'expect_by_platform': {'darwin': 'libprotoc 36.2', 'linux': 'libprotoc 3.12.4'}}
    for platform, version in platform_tool['expect_by_platform'].items():
        with patch.object(module.sys, 'platform', platform):
            assert module.tool_version(consumer, platform_tool) == version
    with patch.object(module.sys, 'platform', 'unknown-os'):
        try:
            module.tool_version(consumer, platform_tool)
        except module.Error as error:
            assert 'no exact tool version declared for platform' in str(error)
        else:
            raise AssertionError('unknown platform version was accepted')
    cases += 1
    print(f'ok {cases}: exact platform versions preserve macOS/Linux assertions and reject unknown platforms', flush=True)
    identity_source = b'syntax="proto3"; package example.api; message Value {string x=1;} option java_package="https://host/a/*literal*///path";'
    identity_formatted = b"/* comment */ syntax = 'proto3' ; package example . api ; // comment\nmessage /* gap */ Value { string x = 1 ; } option java_package = \"https://host/a/*literal*///path\" ;"
    assert module.schema_identity(identity_source) == module.schema_identity(identity_formatted)
    assert module.schema_identity(identity_source)[0] != module.schema_identity(identity_source.replace(b'/path', b'/other'))[0]
    assert module.schema_identity(identity_source)[1].isdisjoint(module.schema_identity(identity_source.replace(b'Value', b'Other'))[1])
    cases += 1
    print(f'ok {cases}: stable schema identity preserves strings and distinguishes qualified definitions', flush=True)
    option_identity = module.schema_identity((args.source / 'wendy/options.proto').read_bytes())[1]
    assert option_identity == {(b'wendy', b'extension', b'signed_request'),
                               (b'wendy', b'extension', b'device_signed_request')}
    nested_options = b'package wendy; message VendorOptions { extend .google.protobuf.MethodOptions { bool signed_request = 51001 [deprecated = true]; } }'
    assert (b'wendy', b'extension', b'VendorOptions.signed_request') in module.schema_identity(nested_options)[1]
    assert module.schema_identity(nested_options)[1].isdisjoint(option_identity)
    cases += 1
    print(f'ok {cases}: actual shared extension fields and distinct message-scoped extensions have qualified identities', flush=True)
    # Real signals in separate ordinary-user processes. No syscall or runner
    # function is mocked: observe an actual replacement, then terminate.
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        cancelled = scratch / ('cancel-' + signum.name)
        (cancelled / 'generated').mkdir(parents=True)
        first = cancelled / 'generated/output-00000.pb.go'
        pin = cancelled / 'contracts.json'
        first.write_bytes(b'original output'); first.chmod(0o444)
        pin.write_bytes(b'original pin'); pin.chmod(0o444)
        process = subprocess.Popen([sys.executable, '-B', str(HERE / 'test-contracts.py'),
                                    '--installation-child', str(cancelled)],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            started = time.monotonic()
            while first.read_bytes() != b'NEW output':
                assert process.poll() is None, 'child exited before an observed replacement'
                assert time.monotonic() - started < 30, 'cancellation observation timed out'
                time.sleep(.001)
            os.kill(process.pid, signum)
            output = process.communicate(timeout=30)[0]
            assert process.returncode != 0 and signum.name in output, output
            assert first.read_bytes() == b'original output' and first.stat().st_mode & 0o777 == 0o444
            assert pin.read_bytes() == b'original pin' and pin.stat().st_mode & 0o777 == 0o444
            assert [p.name for p in (cancelled / 'generated').iterdir()] == ['output-00000.pb.go']
            cases += 1
            print(f'ok {cases}: real {signum.name} during install restores outputs/pin/modes', flush=True)
        finally:
            if process.poll() is None:
                process.kill(); process.wait()
    # Exercise the exact bookkeeping windows with real replacements/deletions
    # and a real SIGTERM immediately after the syscall returns.
    for operation in ('replace', 'unlink'):
        boundary = scratch / ('signal-boundary-' + operation)
        boundary.mkdir()
        (boundary / 'first').write_bytes(b'old output')
        (boundary / 'stale').write_bytes(b'old stale')
        (boundary / 'contracts.json').write_bytes(b'old pin')
        native = getattr(module.os, operation)
        native_replace = module.os.replace
        fired = False
        rollback_signal = False
        original_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        def terminate_after_mutation(*argv, **kwargs):
            global fired
            result = native(*argv, **kwargs)
            target = Path(argv[-1] if operation == 'replace' else argv[0])
            if not fired and target == boundary / ('first' if operation == 'replace' else 'stale'):
                fired = True
                os.kill(os.getpid(), signal.SIGTERM)
            return result
        def terminate_during_restore(src, dst):
            global rollback_signal
            result = native_replace(src, dst)
            if fired and Path(dst) == boundary / 'stale' and not rollback_signal:
                rollback_signal = True
                os.kill(os.getpid(), signal.SIGTERM)
            return result
        try:
            with patch.object(module.os, operation, side_effect=terminate_after_mutation):
                if operation == 'unlink':
                    with patch.object(module.os, 'replace', side_effect=terminate_during_restore):
                        module.install(boundary, {'first': b'new output', 'contracts.json': b'new pin'},
                                       {'first': b'old output', 'stale': b'old stale'})
                else:
                    module.install(boundary, {'first': b'new output', 'contracts.json': b'new pin'},
                                   {'first': b'old output', 'stale': b'old stale'})
        except module.Error as error:
            assert 'SIGTERM' in str(error), str(error)
        else:
            raise AssertionError('bookkeeping-window cancellation was swallowed')
        assert operation != 'unlink' or rollback_signal, 'repeated termination during rollback was not exercised'
        assert fired and (boundary / 'first').read_bytes() == b'old output'
        assert (boundary / 'stale').read_bytes() == b'old stale'
        assert (boundary / 'contracts.json').read_bytes() == b'old pin'
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask
        assert {sig: signal.getsignal(sig) for sig in original_handlers} == original_handlers
        cases += 1
        print(f'ok {cases}: SIGTERM at {operation} bookkeeping boundary restores all files/handlers', flush=True)
    if os.geteuid() != 0:
        # Real permissions, no mocked syscall. Fail deleting a stale file only
        # AFTER an output, a new file and the pin have all been installed.
        permissions = scratch / 'permissions-rollback'
        (permissions / 'out').mkdir(parents=True)
        (permissions / 'blocked').mkdir()
        first = permissions / 'out/first.pb.go'
        pin = permissions / 'contracts.json'
        stale = permissions / 'blocked/stale.pb.go'
        first.write_bytes(b'original output'); first.chmod(0o444)
        pin.write_bytes(b'original pin'); pin.chmod(0o444)
        stale.write_bytes(b'original stale'); stale.chmod(0o444)
        (permissions / 'blocked').chmod(0o555)
        try:
            try:
                module.install(permissions,
                    {'out/first.pb.go': b'NEW output', 'out/new.pb.go': b'NEW file', 'contracts.json': b'NEW pin'},
                    {'out/first.pb.go': b'original output', 'blocked/stale.pb.go': b'original stale'})
            except PermissionError as error:
                assert 'blocked/stale.pb.go' in str(error), str(error)
            else:
                raise AssertionError('real permission failure was swallowed')
            for path, data in [(first, b'original output'), (pin, b'original pin'), (stale, b'original stale')]:
                assert path.read_bytes() == data
                assert path.stat().st_mode & 0o777 == 0o444
            assert not (permissions / 'out/new.pb.go').exists()
            cases += 1
            print(f'ok {cases}: real permission rollback restores bytes/modes, pin and new-file absence', flush=True)
        finally:
            (permissions / 'blocked').chmod(0o755)
    rollback = scratch / 'rollback'
    rollback.mkdir()
    (rollback / 'first').write_bytes(b'old')
    (rollback / 'contracts.json').write_bytes(original_pin)
    replace = module.os.replace
    calls = 0

    def fail_second(src, dst):
        global calls
        calls += 1
        if calls == 2:
            raise OSError('injected replacement failure')
        return replace(src, dst)

    try:
        with patch.object(module.os, 'replace', side_effect=fail_second):
            module.install(rollback, {'first': b'new', 'contracts.json': b'new pin'}, {'first': b'old'})
    except OSError:
        pass
    else:
        raise AssertionError('injected failure was swallowed')
    assert (rollback / 'first').read_bytes() == b'old'
    assert (rollback / 'contracts.json').read_bytes() == original_pin
    cases += 1
    print(f'ok {cases}: installation rollback preserves pin and output', flush=True)
    # Supplemental injection checks diagnostics and continued restoration if a
    # restore itself fails. The permission regression above is entirely native.
    diagnostics = scratch / 'rollback-diagnostics'
    diagnostics.mkdir()
    for name in ('first', 'second', 'contracts.json'):
        (diagnostics / name).write_bytes(b'old')
    calls = 0
    def primary_and_restore_failure(src, dst):
        global calls
        calls += 1
        if calls == 3:
            raise OSError('PRIMARY installation failure')
        if calls == 4:
            raise OSError('ROLLBACK second-file failure')
        return replace(src, dst)
    try:
        with patch.object(module.os, 'replace', side_effect=primary_and_restore_failure):
            module.install(diagnostics, {'first': b'new', 'second': b'new', 'contracts.json': b'new'}, {})
    except module.Error as error:
        assert 'PRIMARY installation failure' in str(error) and 'ROLLBACK second-file failure' in str(error), str(error)
    else:
        raise AssertionError('primary/rollback failures were swallowed')
    assert calls == 5 and (diagnostics / 'first').read_bytes() == b'old'
    assert (diagnostics / 'contracts.json').read_bytes() == b'old'
    cases += 1
    print(f'ok {cases}: rollback attempts all mutations and retains primary/restore diagnostics', flush=True)
    print(f'Passed {cases} real consumer controls; branch-only commit {branch_only}', flush=True)
