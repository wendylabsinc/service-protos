#!/usr/bin/env python3
"""Exercise the runner with a real, prepared consumer fixture and pinned tools.

python3 tools/test-contracts.py --consumer /scratch/consumer --source /repo/service-protos
The consumer contains contracts.json, buf.gen.yaml, real generated output and
local import inputs. It is copied, never modified. Source master and the schema
pin must already be fetched locally. Tests preserve real history and introduce
one actual branch-only commit. URL rewriting is scoped to child processes.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
URL = 'https://github.com/wendylabsinc/service-protos.git'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--consumer', type=Path, required=True)
parser.add_argument('--source', type=Path, required=True)
args = parser.parse_args()


def git(*argv, cwd=None, env=None):
    return subprocess.check_output(['git', *argv], cwd=cwd, env=env, text=True).strip()


with tempfile.TemporaryDirectory(prefix='test-contracts-') as tmp:
    scratch = Path(tmp)
    source = scratch / 'source'
    consumer = scratch / 'consumer'
    shutil.copytree(args.consumer, consumer, ignore=shutil.ignore_patterns('.git', '.build', 'Build'))
    git('init', '-q', str(consumer))
    cfg = json.loads((consumer / 'contracts.json').read_text())
    original_pin = (consumer / 'contracts.json').read_bytes()
    original_template = (consumer / 'buf.gen.yaml').read_bytes()
    git('init', '-q', '--initial-branch=initial', str(source))
    git('fetch', '-q', str(args.source.resolve()), 'refs/remotes/origin/master:refs/heads/master', cfg['commit'], cwd=source)
    git('checkout', '-q', 'master', cwd=source)
    git('config', 'user.name', 'Contract test', cwd=source)
    git('config', 'user.email', 'contracts@example.invalid', cwd=source)
    env = os.environ.copy()
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(scratch / 'gitconfig'),
               GIT_TERMINAL_PROMPT='0', CONTRACTS_RUNNER=str(HERE.parent))
    # Retain existing scoped CI credentials; append only this test's URL rewrite.
    count = int(env.get('GIT_CONFIG_COUNT', '0'))
    env[f'GIT_CONFIG_KEY_{count}'] = f'url.file://{source}.insteadOf'
    env[f'GIT_CONFIG_VALUE_{count}'] = URL
    env[f'GIT_CONFIG_KEY_{count + 1}'] = 'http.https://example.invalid/.extraheader'
    env[f'GIT_CONFIG_VALUE_{count + 1}'] = 'AUTHORIZATION: synthetic-contract-test'
    env['GIT_CONFIG_COUNT'] = str(count + 2)
    git('checkout', '-q', '-b', 'branch-only', cfg['commit'], cwd=source)
    git('-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
        'commit', '-q', '--allow-empty', '-m', 'Unmerged control', cwd=source)
    branch_only = git('rev-parse', 'HEAD', cwd=source)
    git('checkout', '-q', 'master', cwd=source)
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

    invoke(['check'])
    out = consumer / cfg['outputs'][0]['path']
    generated = next(out.rglob('*.pb.swift'))
    saved = generated.read_bytes()
    generated.unlink()
    invoke(['check'], 'missing:')
    generated.write_bytes(saved)
    generated.write_bytes(saved + b'\n// stale\n')
    invoke(['check'], 'changed:')
    generated.write_bytes(saved)
    extra = out / 'extra.pb.swift'
    extra.write_bytes(saved)
    invoke(['check'], 'extra:')
    manual = out / 'Manual.swift'
    manual.write_text('// handwritten\n')
    invoke(['generate'])
    assert not extra.exists() and manual.read_text() == '// handwritten\n'
    assert generated.stat().st_mode & 0o777 == 0o644
    preserve = out / 'Preserved.pb.swift'
    preserve.write_text('// preserved consumer-owned output\n')
    excluded = dict(cfg, outputs=[{**cfg['outputs'][0], 'exclude': ['Preserved.pb.swift']}, *cfg['outputs'][1:]])
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
    local = consumer / 'local/authorization.proto'
    local.write_text('syntax = "proto3";\n')
    allowed = dict(cfg, exceptions={**cfg.get('exceptions', {}),
                                  'local/authorization.proto': 'Real local schema exception control'})
    write_config(allowed)
    invoke(['check'])
    local.unlink()
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
    write_config(cfg)
    fixture.unlink()
    bad_fixture = dict(cfg, fixtures={'conformance/absent.json': 'test-fixtures/set.json'})
    write_config(bad_fixture)
    invoke(['generate'], 'git failed')
    invoke(['bump', cfg['commit']], 'git failed')
    write_config(cfg)
    invoke(['bump', branch_only], 'not an ancestor')
    changed_pin = dict(cfg, commit=branch_only)
    write_config(changed_pin)
    invoke(['check'], 'not an ancestor')
    write_config(cfg)
    bad = dict(cfg, paths=[*cfg['paths'], 'missing.proto'])
    write_config(bad)
    invoke(['generate'], 'selected schema missing from pin')
    invoke(['bump', cfg['commit']], 'selected schema missing from pin')
    write_config(cfg)
    template = json.loads(original_template)
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
    # All fetches fail through real Git, without a mock returning success.
    key = f'GIT_CONFIG_KEY_{count}'
    env[key] = f'url.file://{scratch / "unavailable"}.insteadOf'
    invoke(['generate'], 'git failed')
    invoke(['bump', cfg['commit']], 'git failed')
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
    git('checkout', '-q', 'master', cwd=source)
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
    print(f'Passed {cases} real consumer controls; branch-only commit {branch_only}', flush=True)
