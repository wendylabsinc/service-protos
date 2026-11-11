#!/usr/bin/env python3
"""Pinned shared generation. Config: contracts.json plus JSON-form buf.gen.yaml.

Run from the consumer root: contracts.sh check | generate | bump <fullsha>.
Tool installation belongs to the consumer's existing locked toolchain setup.
There are deliberately no install commands, arbitrary hooks, or implicit cleaning.
"""
import fnmatch
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile

SOURCE = 'https://github.com/wendylabsinc/service-protos.git'
# Keep credential configuration (including scoped HTTP headers) in the environment.
# Only caller-repository redirection is removed, as in check-pin.sh.
for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE',
            'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES',
            'GIT_SHALLOW_FILE', 'GIT_REPLACE_REF_BASE', 'GIT_GRAFT_FILE'):
    os.environ.pop(key, None)


class Error(Exception):
    pass


def run(args, cwd=None, capture=False):
    # Never print environment values or command lines: Git auth may be inherited.
    try:
        return subprocess.run(args, cwd=cwd, check=True,
                              stdout=subprocess.PIPE if capture else None).stdout
    except FileNotFoundError:
        raise Error(f'required tool not found: {Path(args[0]).name}') from None
    except subprocess.CalledProcessError as e:
        raise Error(f'{Path(args[0]).name} failed (exit {e.returncode})') from None


def relative(value):
    if not isinstance(value, str) or not value or '\\' in value:
        raise Error(f'invalid relative path: {value!r}')
    p = PurePosixPath(value)
    if p.is_absolute() or any(x in ('', '.', '..', '.git') for x in value.split('/')):
        raise Error(f'unsafe relative path: {value!r}')
    return value


def safe(root, value):
    p = root
    for part in relative(value).split('/'):
        p = p / part
        if p.is_symlink():
            raise Error(f'unsafe symlink: {value}')
    return p


def load(path):
    try:
        return json.loads(path.read_text())
    except (ValueError, OSError) as e:
        raise Error(f'{path.name}: requires JSON syntax (also valid YAML): {e}') from None


def fields(obj, allowed, required=()):
    if not isinstance(obj, dict) or set(obj) - set(allowed) or set(required) - set(obj):
        raise Error(f'invalid configuration fields; allowed: {", ".join(allowed)}')


def validate(root, cfg, template):
    fields(cfg, ('commit', 'paths', 'stage', 'imports', 'exceptions', 'outputs',
                 'fixtures', 'tools', 'compiler', 'python_import_prefix', 'repair'), ('commit', 'paths', 'outputs', 'tools', 'repair'))
    if not re.fullmatch('[0-9a-f]{40}', cfg['commit']):
        raise Error('commit must be a full lowercase 40-hex SHA')
    if not cfg['paths'] or len(set(cfg['paths'])) != len(cfg['paths']):
        raise Error('paths must be nonempty and unique')
    for p in cfg['paths']:
        relative(p)
        if not p.endswith('.proto'):
            raise Error('paths must select individual .proto files')
    for key in ('stage', 'imports', 'fixtures'):
        for src, dst in cfg.get(key, {}).items():
            relative(src)
            safe(root, dst) if key == 'fixtures' else relative(dst)
    if set(cfg.get('stage', {})) - set(cfg['paths']):
        raise Error('stage keys must name selected paths')
    for src in cfg.get('imports', {}):
        if not safe(root, src).is_file():
            raise Error(f'local import is missing: {src}')
    for path, reason in cfg.get('exceptions', {}).items():
        if not isinstance(reason, str) or not reason.strip() or not safe(root, path).is_file():
            raise Error(f'exception needs a reason and an existing regular file: {path}')
    fields(template, ('version', 'plugins'), ('version', 'plugins'))
    if template['version'] != 'v2' or not template['plugins']:
        raise Error('buf.gen.yaml must use v2 and select plugins')
    if not cfg['tools']:
        raise Error('tools must enforce the existing exact tool versions')
    checked = []
    for tool in cfg['tools']:
        fields(tool, ('command', 'expect'), ('command', 'expect'))
        if not isinstance(tool['command'], list) or not tool['command'] or not tool['expect']:
            raise Error('tool requires a version command and exact expected stdout')
        checked.append(tool['command'][0])
    if cfg.get('compiler') and cfg['compiler'] not in checked:
        raise Error('compiler needs an exact version check in tools')
    if 'buf' not in checked:
        raise Error('tools must check the exact buf version')
    dirs = []
    for out in cfg['outputs']:
        fields(out, ('path', 'patterns', 'exclude'), ('path', 'patterns'))
        safe(root, out['path'])
        if out['path'] in ('contracts.json', 'buf.gen.yaml'):
            raise Error('output roots must not overwrite configuration')
        if not out['patterns']:
            raise Error('output ownership needs explicit patterns')
        for pattern in out['patterns'] + out.get('exclude', []):
            relative(pattern)
        for other in dirs:
            if out['path'] == other or out['path'].startswith(other + '/') or other.startswith(out['path'] + '/'):
                raise Error('output roots must not overlap')
        dirs.append(out['path'])
    if not dirs:
        raise Error('outputs must be nonempty')
    if len(set(cfg.get('fixtures', {}).values())) != len(cfg.get('fixtures', {})):
        raise Error('fixture destinations must be unique')
    for dst in cfg.get('fixtures', {}).values():
        if dst in ('contracts.json', 'buf.gen.yaml') or any(dst == d or dst.startswith(d + '/') for d in dirs):
            raise Error('fixtures must not overlap configuration or output roots')
    for plugin in template['plugins']:
        fields(plugin, ('local', 'protoc_builtin', 'protoc_path', 'out', 'opt', 'strategy'), ('out',))
        if ('local' in plugin) == ('protoc_builtin' in plugin):
            raise Error('plugin must select exactly one of local or protoc_builtin')
        if 'protoc_builtin' in plugin and not re.fullmatch(r'[a-z][a-z0-9_-]*', plugin['protoc_builtin']):
            raise Error('invalid builtin generator name')
        if 'local' in plugin and 'protoc_path' in plugin:
            raise Error('protoc_path is only valid for protoc_builtin')
        if plugin.get('strategy', 'directory') not in ('all', 'directory'):
            raise Error('plugin strategy must be all or directory')
        relative(plugin['out'])
        if plugin['out'] not in dirs:
            raise Error('each plugin output needs explicit ownership')
        command = plugin.get('local', plugin.get('protoc_path', 'protoc'))
        command = command if isinstance(command, str) else command[0]
        if command not in checked:
            raise Error(f'local plugin needs an exact version check: {command}')
    prefix = cfg.get('python_import_prefix')
    if prefix and (not isinstance(prefix, str) or not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*', prefix)):
        raise Error('python_import_prefix must be a Python package name')
    if not cfg['repair'] or not isinstance(cfg['repair'], str):
        raise Error('repair must give the exact consumer generation command')


def owned(root, out):
    directory = safe(root, out['path'])
    result = {}
    if not directory.exists():
        return result
    if not directory.is_dir():
        raise Error(f'output must be a directory: {out["path"]}')
    for parent, dirs, files in os.walk(directory, followlinks=False):
        for name in dirs + files:
            path = Path(parent) / name
            rel = path.relative_to(directory).as_posix()
            # Refuse symlinks even when excluded: traversal must never depend on them.
            if path.is_symlink():
                raise Error(f'unsafe symlink in output: {out["path"]}/{rel}')
            if not path.is_file():
                continue
            if any(fnmatch.fnmatchcase(rel, p) for p in out['patterns']) and not any(
                    fnmatch.fnmatchcase(rel, p) for p in out.get('exclude', [])):
                result[f'{out["path"]}/{rel}'] = path.read_bytes()
    return result


def source_guard(root, cfg, catalogue):
    names = {p.name for p in catalogue.rglob('*.proto')}
    if not names:
        raise Error('empty shared schema catalogue')
    # Include known former spellings, even when an old pin predates the catalogue path.
    names.add('sensorlink.proto')
    forbidden = {'Proto', 'proto', 'service-protos', 'third_party/service-protos',
                 'clip-store/proto', 'clip-store/service-protos', 'cloud-proto',
                 'WendyCompanionSDK/Sources/WendyProtos'}
    entries = run(['git', 'ls-files', '--stage', '-z'], cwd=root, capture=True).decode().split('\0')
    for entry in filter(None, entries):
        metadata, path = entry.split('\t', 1)
        if metadata.startswith('160000 ') and (path in forbidden or Path(path).name.lower() in ('proto', 'service-protos') or any(
                path == out['path'] or path.startswith(out['path'] + '/') for out in cfg['outputs'])):
            raise Error(f'local shared schema gitlink: {path}')
    # The maintained tree is Git's tracked plus nonignored untracked files.
    # Explicitly inspect former source locations even if ignored (fixtures may
    # live there, but maintained protobuf copies and gitlinks may not).
    local = set(filter(None, run(['git', 'ls-files', '--cached', '--others',
                                 '--exclude-standard', '-z', '--', '*.proto'],
                                cwd=root, capture=True).decode().split('\0')))
    top_names = {p.name for p in root.iterdir()}
    for alias in forbidden:
        # Avoid treating Proto and proto as two roots on case-insensitive Macs.
        if alias.split('/')[0] not in top_names:
            continue
        directory = root / alias
        if directory.is_symlink() or (directory / '.git').exists():
            raise Error(f'local shared source checkout or symlink: {alias}')
        if directory.is_dir():
            for parent, dirs, files in os.walk(directory, followlinks=False):
                for name in dirs + files:
                    path = Path(parent) / name
                    if path.is_symlink():
                        raise Error(f'unsafe symlink in local source: {path.relative_to(root)}')
                    if name.endswith('.proto'):
                        local.add(path.relative_to(root).as_posix())
    for rel in sorted(local):
        if Path(rel).name in names and rel not in cfg.get('exceptions', {}):
            raise Error(f'local shared schema copy or alias: {rel}')
        safe(root, rel)


def prepare(root, cfg, template, scratch, revision):
    # Fetch checker policy independently of the immutable schema pin. Reuse its
    # ancestry policy verbatim; do not reimplement merge-base checks here.
    policy = scratch / 'policy'
    run(['git', 'init', '--bare', '--quiet', str(policy)])
    run(['git', '-C', str(policy), 'fetch', '--quiet', '--depth=1', '--no-tags', SOURCE, 'master'])
    checker = run(['git', '-C', str(policy), 'show', 'FETCH_HEAD:tools/check-pin.sh'], capture=True)
    if not checker.strip():
        raise Error('canonical pin checker is empty')
    (scratch / 'check-pin.sh').write_bytes(checker)
    run(['bash', str(scratch / 'check-pin.sh'), revision])
    for tool in cfg['tools']:
        actual = run(tool['command'], cwd=root, capture=True).decode().strip()
        if actual != tool['expect']:
            raise Error(f'{Path(tool["command"][0]).name} version mismatch: expected {tool["expect"]!r}, found {actual!r}')
    catalogue = scratch / 'catalogue'
    run(['buf', 'export', f'{SOURCE}#ref={revision}', '--output', str(catalogue)])
    source_guard(root, cfg, catalogue)
    selected = scratch / 'selected'
    run(['buf', 'export', f'{SOURCE}#ref={revision}', '--output', str(selected),
         '--exclude-imports', *[a for p in cfg['paths'] for a in ('--path', p)]])
    staged = scratch / 'staged'
    staged.mkdir()
    paths = []
    for src in cfg['paths']:
        dst = cfg.get('stage', {}).get(src, src)
        path = safe(staged, dst)
        if path.exists():
            raise Error(f'duplicate staged path: {dst}')
        path.parent.mkdir(parents=True, exist_ok=True)
        input_path = safe(selected, src)
        if not input_path.is_file():
            raise Error(f'selected schema missing from pin: {src}')
        shutil.copyfile(input_path, path)
        paths.append(dst)
    # Copy imported dependencies, without generating them; selected staging wins.
    for path in catalogue.rglob('*.proto'):
        rel = path.relative_to(catalogue).as_posix()
        if rel in cfg['paths']:
            continue
        dst = safe(staged, rel)
        if not dst.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, dst)
    seen_imports = set()
    for src, dst in cfg.get('imports', {}).items():
        if dst in paths or dst in seen_imports:
            raise Error(f'local import overlaps another staged input: {dst}')
        seen_imports.add(dst)
        path = safe(staged, dst)
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(safe(root, src), path)
    generated = scratch / 'generated'
    config = scratch / 'buf.gen.yaml'
    # Resolve local executables relative to consumer, while Buf runs in scratch.
    for plugin in template['plugins']:
        key = 'local' if 'local' in plugin else 'protoc_path'
        cmd = plugin.get(key, 'protoc')
        first = cmd if isinstance(cmd, str) else cmd[0]
        if '/' in first and not Path(first).is_absolute():
            resolved = str(safe(root, first.removeprefix('./')))
            plugin[key] = resolved if isinstance(cmd, str) else [resolved, *cmd[1:]]
    config.write_text(json.dumps(template))
    if cfg.get('compiler'):
        # Buf's local-plugin requests omit compiler_version. Go stamps that as
        # '(unknown)', so retain the consumer's real protoc when byte parity
        # requires it. Options/output paths still come only from buf.gen.yaml.
        compiler = cfg['compiler']
        if '/' in compiler and not Path(compiler).is_absolute():
            compiler = str(safe(root, compiler.removeprefix('./')))
        for index, plugin in enumerate(template['plugins']):
            plugin_args = []
            command = [compiler]
            if 'local' in plugin:
                if not isinstance(plugin['local'], str):
                    raise Error('compiler adapter requires local plugin executable paths')
                executable = shutil.which(plugin['local'])
                if not executable:
                    raise Error(f'local plugin executable missing: {plugin["local"]}')
                alias = f'contracts{index}'
                plugin_args = [f'--plugin=protoc-gen-{alias}={executable}']
            else:
                alias = plugin['protoc_builtin']
                command = plugin.get('protoc_path', compiler)
                command = [command] if isinstance(command, str) else command
                if command[0] != compiler:
                    raise Error('builtin protoc_path must use the checked compiler')
            dest = safe(generated, plugin['out'])
            dest.mkdir(parents=True, exist_ok=True)
            opts = plugin.get('opt', [])
            opts = [opts] if isinstance(opts, str) else opts
            groups = [paths] if plugin.get('strategy', 'directory') == 'all' else [
                [p for p in paths if str(PurePosixPath(p).parent) == directory]
                for directory in sorted({str(PurePosixPath(p).parent) for p in paths})]
            for group in groups:
                run([*command, f'--proto_path={staged}', *plugin_args,
                     f'--{alias}_out={dest}',
                     *[f'--{alias}_opt={opt}' for opt in opts], *group], cwd=staged)
    else:
        run(['buf', 'generate', '.', '--template', str(config), '--output', str(generated),
             *[a for p in paths for a in ('--path', p)]], cwd=staged)
    if cfg.get('python_import_prefix'):
        # Console's existing grpcio-tools output lives under app.generated.
        # Preserve that package binding, without changing compiler headers.
        prefix = cfg['python_import_prefix']
        packages = {p.split('/')[0] for p in cfg['paths'] if '/' in p}
        for path in generated.rglob('*_pb2.py'):
            safe(generated, path.relative_to(generated).as_posix())
            content = path.read_text()
            for package in sorted(packages):
                content = content.replace(f'from {package}', f'from {prefix}.{package}')
                content = content.replace(
                    f"BuildTopDescriptorsAndMessages(DESCRIPTOR, '{package}",
                    f"BuildTopDescriptorsAndMessages(DESCRIPTOR, '{prefix}.{package}")
            path.write_text(content)
    expected = {}
    for out in cfg['outputs']:
        files = owned(generated, out)
        if not files:
            raise Error(f'generator produced no owned files for {out["path"]}')
        expected.update(files)
    all_generated = {p.relative_to(generated).as_posix() for p in generated.rglob('*') if p.is_file()}
    if all_generated != set(expected):
        raise Error('generator wrote files outside declared ownership: ' + ', '.join(sorted(all_generated - set(expected))))
    if cfg.get('fixtures'):
        repo = scratch / 'fixtures.git'
        run(['git', 'init', '--bare', '--quiet', str(repo)])
        run(['git', '-C', str(repo), 'fetch', '--quiet', '--no-tags', SOURCE,
             '+refs/heads/*:refs/remotes/source/*', revision])
        for src, dst in cfg['fixtures'].items():
            if dst in expected:
                raise Error(f'fixture overlaps generated output: {dst}')
            expected[dst] = run(['git', '-C', str(repo), 'show', f'{revision}:{src}'], capture=True)
    return expected


def current(root, cfg):
    actual = {}
    for out in cfg['outputs']:
        actual.update(owned(root, out))
    for dst in cfg.get('fixtures', {}).values():
        path = safe(root, dst)
        if path.exists():
            actual[dst] = path.read_bytes()
    return actual


def install(root, expected, actual):
    # Backup every affected file before the first write; roll back a failed install.
    paths = set(expected) | set(actual)
    for rel in paths:
        safe(root, rel)
    saved = {rel: (safe(root, rel).read_bytes() if safe(root, rel).exists() else None) for rel in paths}
    try:
        for rel, data in expected.items():
            path = safe(root, rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            # Atomic file replacement also preserves other hardlink targets.
            fd, tmp = tempfile.mkstemp(prefix='.contracts-', dir=path.parent)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    os.fchmod(stream.fileno(), stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644)
                    stream.write(data)
                os.replace(tmp, path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        for rel in actual.keys() - expected.keys():
            safe(root, rel).unlink()
    except BaseException:
        for rel, data in saved.items():
            path = safe(root, rel)
            if data is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(data)
        raise


def main():
    if len(sys.argv) not in (2, 3) or sys.argv[1] not in ('check', 'generate', 'bump') or (
            (sys.argv[1] == 'bump') != (len(sys.argv) == 3)):
        raise Error('usage: contracts.sh check | generate | bump <full-40-hex-sha>')
    root = Path.cwd().resolve()
    pin = safe(root, 'contracts.json')
    cfg = load(pin)
    try:
        template = load(safe(root, 'buf.gen.yaml'))
        validate(root, cfg, template)
        revision = sys.argv[2] if sys.argv[1] == 'bump' else cfg['commit']
        if not re.fullmatch('[0-9a-f]{40}', revision):
            raise Error('bump requires a full lowercase 40-hex SHA')
        with tempfile.TemporaryDirectory(prefix='contracts-') as tmp:
            expected = prepare(root, cfg, template, Path(tmp), revision)
            actual = current(root, cfg)
            if sys.argv[1] == 'check':
                changes = sorted(p for p in actual.keys() | expected.keys() if actual.get(p) != expected.get(p))
                if changes:
                    for p in changes:
                        kind = 'missing' if p not in actual else 'extra' if p not in expected else 'changed'
                        print(f'{kind}: {p}', file=sys.stderr)
                    raise Error('shared generated output or fixtures drifted')
            else:
                if sys.argv[1] == 'bump':
                    cfg['commit'] = revision
                    expected['contracts.json'] = (json.dumps(cfg, indent=2) + '\n').encode()
                install(root, expected, actual)
    except (Error, OSError) as e:
        raise Error(f'{e}\nRepair from the consumer root: {cfg.get("repair", "bash Scripts/contracts.sh generate")}') from None
    print(f'contracts {sys.argv[1]} succeeded at {revision}')


if __name__ == '__main__':
    try:
        main()
    except (Error, OSError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        sys.exit(1)
