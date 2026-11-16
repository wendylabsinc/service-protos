#!/usr/bin/env python3
"""Pinned shared generation. Config: contracts.json, buf.gen.yaml, optional contracts-exceptions.yaml.

Run from the consumer root: contracts.sh check | generate | bump <fullsha>.
check accepts --pin-only or --sources-only; generate accepts --fixtures-only.
plugin_paths optionally selects declared source paths per plugin, in Buf order.
Local generated inputs must also be declared imports and literal exceptions.
contracts-exceptions.yaml maps exact local file paths to reasons (no wildcards).
Tool assertions read Package.resolved/npm/uv lockfiles; versions stay there.
Python 3.11+ is required (stdlib TOML support).
Install contracts-requirements.txt into the runner's Python environment once.
Tool installation belongs to the consumer's existing locked toolchain setup.
There are deliberately no install commands, arbitrary hooks, or implicit cleaning.
"""
from contextlib import contextmanager
import fnmatch
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import tarfile

SOURCE = 'https://github.com/wendylabsinc/service-protos.git'
# Keep credential configuration (including scoped HTTP headers) in the environment.
# Only caller-repository redirection is removed, as in check-pin.sh.
for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE',
            'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES',
            'GIT_SHALLOW_FILE', 'GIT_REPLACE_REF_BASE', 'GIT_GRAFT_FILE'):
    os.environ.pop(key, None)


class Error(Exception):
    pass


def run(args, cwd=None, capture=False, env=None):
    # Never print environment values or command lines: Git auth may be inherited.
    try:
        return subprocess.run(args, cwd=cwd, check=True, env=env,
                              stdout=subprocess.PIPE if capture else None).stdout
    except FileNotFoundError:
        raise Error(f'required tool not found: {Path(args[0]).name}') from None
    except subprocess.CalledProcessError as e:
        raise Error(f'{Path(args[0]).name} failed (exit {e.returncode})') from None


def walk_error(error):
    raise error


def relative(value):
    if not isinstance(value, str) or not value or '\\' in value:
        raise Error(f'invalid relative path: {value!r}')
    p = PurePosixPath(value)
    if p.is_absolute() or any(x in ('', '.', '..') or x.lower() == '.git' for x in value.split('/')):
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
        if path.suffix != '.yaml':
            return json.loads(path.read_text())
        import importlib.metadata
        try:
            import yaml
        except ImportError:
            raise Error('install runner dependencies: python3 -m pip install -r ' +
                        str(Path(__file__).with_name('contracts-requirements.txt'))) from None
        required = Path(__file__).with_name('contracts-requirements.txt').read_text().strip().split('==')[1]
        if importlib.metadata.version('PyYAML') != required:
            raise Error(f'runner requires PyYAML {required}')
        class UniqueLoader(yaml.SafeLoader):
            def construct_mapping(self, node, deep=False):
                mapping = super().construct_mapping(node, deep=deep)
                seen = set()
                for key_node, _ in node.value:
                    key = self.construct_object(key_node, deep=deep)
                    if key in seen:
                        raise yaml.constructor.ConstructorError(
                            'while constructing a mapping', node.start_mark,
                            f'duplicate key {key!r}', key_node.start_mark)
                    seen.add(key)
                return mapping
        try:
            return yaml.load(path.read_text(), Loader=UniqueLoader)
        except yaml.YAMLError as e:
            raise Error(f'invalid YAML in {path.name}: {e}') from None
    except (ValueError, OSError) as e:
        raise Error(f'cannot read {path.name}: {e}') from None


def tool_version(root, tool):
    if 'expect' in tool:
        return tool['expect']
    if 'expect_by_platform' in tool:
        versions = tool['expect_by_platform']
        if not isinstance(versions, dict) or not versions or set(versions) - {'darwin', 'linux'} or any(
                not isinstance(v, str) or not v for v in versions.values()):
            raise Error('expect_by_platform must map darwin/linux to exact version strings')
        if sys.platform not in versions:
            raise Error(f'no exact tool version declared for platform: {sys.platform}')
        return versions[sys.platform]
    path = safe(root, tool['lockfile'])
    if path.name == 'uv.lock':
        import tomllib
        try:
            lock = tomllib.loads(path.read_text())
        except (ValueError, OSError) as e:
            raise Error(f'invalid uv.lock: {e}') from None
    else:
        lock = load(path)
    if 'pins' in lock:
        matches = [p['state']['version'] for p in lock['pins'] if p['identity'] == tool['package']]
        if len(matches) != 1:
            raise Error(f'package missing or ambiguous in lockfile: {tool["package"]}')
        version = matches[0]
    elif 'packages' in lock:
        package = lock['packages'].get('node_modules/' + tool['package'], {})
        version = package.get('version')
    elif 'package' in lock:
        matches = [p['version'] for p in lock['package'] if p['name'] == tool['package']]
        if len(matches) != 1:
            raise Error(f'package missing or ambiguous in uv.lock: {tool["package"]}')
        version = matches[0]
    else:
        raise Error('version source must be Package.resolved, npm package-lock.json or uv.lock')
    if not isinstance(version, str) or not version:
        raise Error(f'package version missing in lockfile: {tool["package"]}')
    return tool.get('prefix', '') + version


def fields(obj, allowed, required=()):
    if not isinstance(obj, dict) or set(obj) - set(allowed) or set(required) - set(obj):
        raise Error(f'invalid configuration fields; allowed: {", ".join(allowed)}')


def validate(root, cfg, template, exceptions):
    fields(cfg, ('commit', 'paths', 'stage', 'imports', 'outputs', 'plugin_paths',
                 'fixtures', 'tools', 'compiler', 'python_import_prefix', 'swift_public_imports', 'cloud_signed_methods', 'repair'), ('commit', 'paths', 'outputs', 'tools', 'repair'))
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
    for path, reason in exceptions.items():
        if not isinstance(reason, str) or not reason.strip() or not safe(root, path).is_file():
            raise Error(f'exception needs a reason and an existing regular file: {path}')
    fields(template, ('version', 'plugins'), ('version', 'plugins'))
    if template['version'] != 'v2' or not template['plugins']:
        raise Error('buf.gen.yaml must use v2 and select plugins')
    if not cfg['tools']:
        raise Error('tools must enforce the existing exact tool versions')
    checked = []
    for tool in cfg['tools']:
        fields(tool, ('command', 'expect', 'expect_by_platform', 'lockfile', 'package', 'prefix', 'executable'), ('command',))
        if sum(key in tool for key in ('expect', 'lockfile', 'expect_by_platform')) != 1:
            raise Error('tool needs exactly one version source: expect, lockfile or expect_by_platform')
        if 'lockfile' in tool and 'package' not in tool:
            raise Error('lockfile version check needs a package name')
        if not isinstance(tool['command'], list) or not tool['command']:
            raise Error('tool requires a version command and exact expected stdout')
        checked.append(tool.get('executable', tool['command'][0]))
    if cfg.get('compiler') and cfg['compiler'] not in checked:
        raise Error('compiler needs an exact version check in tools')
    for adapter in ('swift_public_imports', 'cloud_signed_methods'):
        if adapter in cfg and cfg[adapter] is not True:
            raise Error(f'{adapter} must be true when enabled')
    if cfg.get('cloud_signed_methods') and 'protoc' not in checked:
        raise Error('Cloud signed methods requires a checked protoc on PATH')
    if 'buf' not in checked:
        raise Error('tools must check the exact buf version')
    dirs = []
    for out in cfg['outputs']:
        fields(out, ('path', 'patterns', 'exclude'), ('path', 'patterns'))
        safe(root, out['path'])
        if out['path'] in ('contracts.json', 'buf.gen.yaml', 'contracts-exceptions.yaml'):
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
        if dst in ('contracts.json', 'buf.gen.yaml', 'contracts-exceptions.yaml') or any(dst == d or dst.startswith(d + '/') for d in dirs):
            raise Error('fixtures must not overlap configuration or output roots')
    subsets = cfg.get('plugin_paths', [cfg['paths']] * len(template['plugins']))
    if not isinstance(subsets, list) or len(subsets) != len(template['plugins']):
        raise Error('plugin_paths must have exactly one list per Buf plugin')
    for subset in subsets:
        if not isinstance(subset, list) or not subset or any(p not in set(cfg['paths']) | set(cfg.get('imports', {})) for p in subset) or len(set(subset)) != len(subset):
            raise Error('plugin_paths must select nonempty unique declared input paths')
        if any(p in cfg.get('imports', {}) and p not in exceptions for p in subset):
            raise Error('generating a local input requires its literal source exception')
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
    for parent, dirs, files in os.walk(directory, followlinks=False, onerror=walk_error):
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


def schema_identity(data):
    # Lexical identity only: comments/spacing are ignored, quoted values are
    # kept whole (URLs and comment markers inside strings are significant).
    # Qualified top-level definitions also identify a copy with local edits.
    tokens = [m.group() for m in re.finditer(
        rb'//[^\r\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_][A-Za-z_0-9]*|[0-9]+|[^\s]',
        data, re.DOTALL) if not m.group().startswith((b'//', b'/*'))]
    package = b''
    definitions = set()
    depth = 0
    scopes = []
    extension_depth = None
    brackets = 0
    for index, token in enumerate(tokens):
        if depth == 0 and token == b'package':
            end = next((i for i in range(index + 1, len(tokens)) if tokens[i] == b';'), len(tokens))
            value = b''.join(tokens[index + 1:end])
            if re.fullmatch(rb'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*', value):
                package = value
        if depth == 0 and token in (b'message', b'enum', b'service') and index + 1 < len(tokens):
            name = tokens[index + 1]
            if re.fullmatch(rb'[A-Za-z_]\w*', name):
                definitions.add((token, name))
        if token == b'extend':
            end = next((i for i in range(index + 1, len(tokens)) if tokens[i] in (b'{', b';')), len(tokens))
            if re.fullmatch(rb'\.?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*', b''.join(tokens[index + 1:end])):
                extension_depth = depth + 1
        if token == b'=' and depth == extension_depth and brackets == 0 and index:
            name = tokens[index - 1]
            if re.fullmatch(rb'[A-Za-z_]\w*', name):
                # Extension names belong to their declaration scope, not the
                # extended type or field number. Distinct vendor options stay distinct.
                definitions.add((b'extension', b'.'.join([s for s in scopes if s] + [name])))
        if token == b'[':
            brackets += 1
        elif token == b']':
            brackets -= 1
        if token == b'{':
            scopes.append(tokens[index - 1] if index > 1 and tokens[index - 2] == b'message' else b'')
            depth += 1
        elif token == b'}':
            if depth == extension_depth:
                extension_depth = None
            if scopes:
                scopes.pop()
            depth -= 1
    normalized = [b's:' + t[1:-1] if t.startswith((b'"', b"'")) else b't:' + t for t in tokens]
    return (hashlib.sha256(b'\0'.join(normalized)).digest(),
            {(package, kind, name) for kind, name in definitions})


def source_guard(root, cfg, catalogues, exceptions):
    schemas = [p for catalogue in catalogues for p in catalogue.rglob('*.proto')]
    names = {p.name for p in schemas}
    parsed = [schema_identity(p.read_bytes()) for p in schemas]
    identities = {fingerprint for fingerprint, _ in parsed}
    definitions = set().union(*(declared for _, declared in parsed))
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
    # Declared local imports are maintained inputs even when Git ignores their
    # cache directory or they were renamed before being staged at a shared path.
    for src, dst in cfg.get('imports', {}).items():
        local.add(src)
        if Path(dst).name in names and src not in exceptions:
            raise Error(f'local shared schema import needs exception: {src}')
    top_names = {p.name for p in root.iterdir()}
    for alias in forbidden:
        # Avoid treating Proto and proto as two roots on case-insensitive Macs.
        if alias.split('/')[0] not in top_names:
            continue
        directory = root / alias
        if directory.is_symlink() or (directory / '.git').exists():
            raise Error(f'local shared source checkout or symlink: {alias}')
        if directory.is_dir():
            for parent, dirs, files in os.walk(directory, followlinks=False, onerror=walk_error):
                for name in dirs + files:
                    path = Path(parent) / name
                    if path.is_symlink():
                        raise Error(f'unsafe symlink in local source: {path.relative_to(root)}')
                    if name.endswith('.proto'):
                        local.add(path.relative_to(root).as_posix())
    for rel in sorted(local):
        path = safe(root, rel)
        if not path.exists():
            continue
        reserved = any(rel.startswith(alias + '/') for alias in forbidden)
        if rel not in exceptions:
            fingerprint, declared = schema_identity(path.read_bytes())
            if reserved or Path(rel).name in names or fingerprint in identities or declared & definitions:
                raise Error(f'local shared schema copy or alias: {rel}')


def collect_output(source, destination, written):
    # Isolate each invocation before reconciling it, including per-directory
    # protoc calls. No later options pass may silently overwrite earlier bytes.
    for parent, dirs, files in os.walk(source, onerror=walk_error):
        for name in dirs + files:
            path = Path(parent) / name
            rel = path.relative_to(source).as_posix()
            safe(source, rel)
            if not path.is_file():
                continue
            if rel.casefold() in written:
                raise Error(f'conflicting plugin output: {rel}')
            written.add(rel.casefold())
            dst = safe(destination, rel)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, dst)


def fetch_policy(scratch):
    # Fetch checker policy independently of the immutable schema pin. Reuse its
    # ancestry policy verbatim; do not reimplement merge-base checks here.
    policy = scratch / 'policy'
    run(['git', 'init', '--bare', '--quiet', str(policy)])
    run(['git', '-C', str(policy), 'fetch', '--quiet', '--depth=1', '--no-tags', SOURCE, 'main'])
    policy_revision = run(['git', '-C', str(policy), 'rev-parse', 'FETCH_HEAD'], capture=True).decode().strip()
    checker = run(['git', '-C', str(policy), 'show', f'{policy_revision}:tools/check-pin.sh'], capture=True)
    if not checker.strip():
        raise Error('canonical pin checker is empty')
    (scratch / 'check-pin.sh').write_bytes(checker)
    return policy, policy_revision


def check_sources(root, cfg, scratch, revision, exceptions, policy, policy_revision):
    # A cheap guard needs Git and the runner, not Buf or language generators.
    # Both identities come from actual Git objects, with no pinned-policy fallback.
    run(['git', '-C', str(policy), 'fetch', '--quiet', '--no-tags', SOURCE,
         '+refs/heads/*:refs/remotes/source/*', revision])
    catalogues = []
    for index, commit in enumerate((policy_revision, revision)):
        catalogue = scratch / f'git-catalogue-{index}'
        data = run(['git', '-C', str(policy), 'archive', '--format=tar', commit, '*.proto'], capture=True)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            for member in archive:
                if member.isdir():
                    continue
                if not member.isfile():
                    raise Error(f'unsafe shared schema archive entry: {member.name}')
                path = safe(catalogue, member.name)
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as stream:
                    path.write_bytes(stream.read())
        catalogues.append(catalogue)
    source_guard(root, cfg, catalogues, exceptions)


def prepare(root, cfg, template, scratch, revision):
    for tool in cfg['tools']:
        expected_version = tool_version(root, tool)
        if not isinstance(expected_version, str) or not expected_version:
            raise Error('tool requires an exact expected version stdout')
        actual = run(tool['command'], cwd=root, capture=True).decode().strip()
        if actual != expected_version:
            raise Error(f'{Path(tool["command"][0]).name} version mismatch: expected {expected_version!r}, found {actual!r}')
    catalogue = scratch / 'catalogue'
    run(['buf', 'export', f'{SOURCE}#ref={revision}', '--output', str(catalogue)])
    # Generation, local staging and fixtures use only the immutable pin.
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
    subsets = cfg.get('plugin_paths', [cfg['paths']] * len(template['plugins']))
    generated.mkdir()
    written = set()
    compiler = cfg.get('compiler')
    if compiler and '/' in compiler and not Path(compiler).is_absolute():
        compiler = str(root / relative(compiler.removeprefix('./')))
    for index, plugin in enumerate(template['plugins']):
        paths = [cfg.get('stage', {}).get(p, cfg.get('imports', {}).get(p, p)) for p in subsets[index]]
        plugin_output = scratch / f'plugin-{index}'
        key = 'local' if 'local' in plugin else 'protoc_path'
        cmd = plugin.get(key, 'protoc')
        first = cmd if isinstance(cmd, str) else cmd[0]
        if '/' in first and not Path(first).is_absolute():
            resolved = str(root / relative(first.removeprefix('./')))
            plugin[key] = resolved if isinstance(cmd, str) else [resolved, *cmd[1:]]
        if compiler:
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
            opts = plugin.get('opt', [])
            opts = [opts] if isinstance(opts, str) else opts
            groups = [paths] if plugin.get('strategy', 'directory') == 'all' else [
                [p for p in paths if str(PurePosixPath(p).parent) == directory]
                for directory in sorted({str(PurePosixPath(p).parent) for p in paths})]
            for request_index, group in enumerate(groups):
                call_output = scratch / f'plugin-{index}-request-{request_index}'
                dest = safe(call_output, plugin['out'])
                dest.mkdir(parents=True, exist_ok=True)
                run([*command, f'--proto_path={staged}', *plugin_args,
                     f'--{alias}_out={dest}',
                     *[f'--{alias}_opt={opt}' for opt in opts], *group], cwd=staged)
                collect_output(call_output, generated, written)
        else:
            config = scratch / 'buf.gen.yaml'
            config.write_text(json.dumps({'version': 'v2', 'plugins': [plugin]}))
            run(['buf', 'generate', '.', '--template', str(config), '--output', str(plugin_output),
                 *[a for p in paths for a in ('--path', p)]], cwd=staged)
            collect_output(plugin_output, generated, written)
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
    if cfg.get('swift_public_imports'):
        # Keep WendyOS's existing public-import pass exactly; this changes API
        # visibility, not generator headers or descriptor bytes.
        for path in generated.rglob('*.swift'):
            content = path.read_text()
            content = re.sub(r'^(import (?:GRPCCore|GRPCProtobuf|SwiftProtobuf|Foundation|FoundationEssentials))$',
                             r'public \1', content, flags=re.MULTILINE)
            content = re.sub(r'^public public import', 'public import', content, flags=re.MULTILINE)
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
    if cfg.get('cloud_signed_methods'):
        # Run Cloud's existing, fixed integration in a disposable repository
        # layout. Both collection and its invariant checks see the SAME pin.
        mirror = scratch / 'cloud-signed-methods'
        script = 'swift/scripts/signed-methods.sh'
        target = safe(mirror, script)
        target.parent.mkdir(parents=True)
        shutil.copyfile(safe(root, script), target)
        (mirror / 'swift/Sources/Proto').mkdir(parents=True)
        for path in safe(root, 'cloud-proto').glob('*.proto'):
            src = safe(root, path.relative_to(root).as_posix())
            dst = mirror / 'cloud-proto' / path.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
        env = dict(os.environ, SHARED_GRPC_API_CONTRACTS_DIR=str(catalogue))
        run(['bash', str(target)], cwd=mirror, env=env)
        destination = 'swift/Sources/Proto/SignedRequestMethods.swift'
        if destination in expected:
            raise Error('Cloud signed methods overlaps plugin output')
        expected[destination] = safe(mirror, destination).read_bytes()
    for dst, data in read_fixtures(cfg, scratch, revision).items():
        if dst in expected:
            raise Error(f'fixture overlaps generated output: {dst}')
        expected[dst] = data
    return expected


def read_fixtures(cfg, scratch, revision):
    expected = {}
    if cfg.get('fixtures'):
        repo = scratch / 'fixtures.git'
        run(['git', 'init', '--bare', '--quiet', str(repo)])
        run(['git', '-C', str(repo), 'fetch', '--quiet', '--no-tags', SOURCE,
             '+refs/heads/*:refs/remotes/source/*', revision])
        for src, dst in cfg['fixtures'].items():
            expected[dst] = run(['git', '-C', str(repo), 'show', f'{revision}:{src}'], capture=True)
    return expected


def current_fixtures(root, cfg):
    actual = {}
    for dst in cfg.get('fixtures', {}).values():
        path = safe(root, dst)
        if path.exists():
            actual[dst] = path.read_bytes()
    return actual


def current(root, cfg):
    actual = {}
    for out in cfg['outputs']:
        actual.update(owned(root, out))
    actual.update(current_fixtures(root, cfg))
    if cfg.get('cloud_signed_methods'):
        destination = 'swift/Sources/Proto/SignedRequestMethods.swift'
        path = safe(root, destination)
        if path.exists():
            actual[destination] = path.read_bytes()
    return actual


def atomic_write(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.contracts-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextmanager
def installation_signals():
    # Handlers record cancellation; they never throw between a replacement and
    # its mutation record or during rollback. Only checkpoints raise it.
    managed = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, managed)
    managed -= old_mask
    previous = {}
    observed = []
    def record(signum, frame):
        if not observed:
            observed.append(signum)
    def checkpoint(final=False):
        if final:
            # Commit boundary: defer later signals until handlers/mask have
            # been restored, with either committed or rolled-back files intact.
            signal.pthread_sigmask(signal.SIG_BLOCK, managed)
        pending = observed or sorted(signal.sigpending() & managed)
        if pending:
            raise Error(f'installation interrupted by {signal.Signals(pending[0]).name}')
    try:
        for signum in managed:
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, record)
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        yield checkpoint
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, managed)
        try:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


def install(root, expected, actual):
    with installation_signals() as checkpoint:
        # Snapshot bytes/modes before the first mutation. Read-only originals can
        # be replaced in writable directories, so rollback must use replacement too.
        saved = {}
        for rel in expected.keys() | actual.keys():
            path = safe(root, rel)
            saved[rel] = (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) if path.exists() else None
        mutated = []
        try:
            checkpoint()
            for rel, data in expected.items():
                path = safe(root, rel)
                atomic_write(path, data, saved[rel][1] if saved[rel] else 0o644)
                mutated.append(rel)
                checkpoint()
            for rel in actual.keys() - expected.keys():
                safe(root, rel).unlink()
                mutated.append(rel)
                checkpoint()
            checkpoint(final=True)
        except BaseException as primary:
            failures = []
            for rel in reversed(mutated):
                try:
                    path = safe(root, rel)
                    if saved[rel] is None:
                        path.unlink(missing_ok=True)
                    else:
                        atomic_write(path, *saved[rel])
                except BaseException as rollback:
                    failures.append(f'{rel}: {type(rollback).__name__}: {rollback}')
            if failures:
                raise Error(f'installation failed: {type(primary).__name__}: {primary}\n'
                            'rollback failed: ' + '; '.join(failures)) from primary
            raise


def compare(expected, actual):
    changes = sorted(p for p in actual.keys() | expected.keys() if actual.get(p) != expected.get(p))
    if changes:
        for p in changes:
            kind = 'missing' if p not in actual else 'extra' if p not in expected else 'changed'
            print(f'{kind}: {p}', file=sys.stderr)
        raise Error('shared generated output or fixtures drifted')


def check_all(root, cfg, template, scratch, revision, exceptions):
    # These are independent diagnostics. Nothing is installed by check, even
    # when a rejected pin or local copy still permits scratch regeneration.
    errors = []
    policy_revision = None
    try:
        policy, policy_revision = fetch_policy(scratch)
    except (Error, OSError) as error:
        errors.extend((f'pin: {error}', f'sources: authoritative policy unavailable: {error}'))
    else:
        try:
            run(['bash', str(scratch / 'check-pin.sh'), revision])
        except (Error, OSError) as error:
            errors.append(f'pin: {error}')
        try:
            check_sources(root, cfg, scratch, revision, exceptions, policy, policy_revision)
            print('shared sources check succeeded')
        except (Error, OSError) as error:
            errors.append(f'sources: {error}')
    try:
        expected = prepare(root, cfg, template, scratch, revision)
        compare(expected, current(root, cfg))
        print('generated output and fixtures check succeeded')
    except (Error, OSError) as error:
        errors.append(f'drift: {error}')
    if errors:
        raise Error('\n'.join(errors))


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else ''
    option = sys.argv[2] if len(sys.argv) == 3 else ''
    if len(sys.argv) not in (2, 3) or command not in ('check', 'generate', 'bump') or (
            command == 'check' and option not in ('', '--pin-only', '--sources-only')) or (
            command == 'generate' and option not in ('', '--fixtures-only')) or (
            command == 'bump' and not option):
        raise Error('usage: contracts.sh check [--pin-only|--sources-only] | generate [--fixtures-only] | bump <full-40-hex-sha>')
    root = Path.cwd().resolve()
    pin = safe(root, 'contracts.json')
    cfg = load(pin)
    try:
        revision = option if command == 'bump' else cfg['commit']
        if not re.fullmatch('[0-9a-f]{40}', revision):
            raise Error('commit must be a full lowercase 40-hex SHA')
        if option != '--pin-only':
            template = load(safe(root, 'buf.gen.yaml'))
            exception_file = safe(root, 'contracts-exceptions.yaml')
            exceptions = (load(exception_file) or {}) if exception_file.exists() else {}
            if not isinstance(exceptions, dict):
                raise Error('contracts-exceptions.yaml must map literal paths to reasons')
            validate(root, cfg, template, exceptions)
        with tempfile.TemporaryDirectory(prefix='contracts-') as tmp:
            scratch = Path(tmp)
            if command == 'check' and not option:
                check_all(root, cfg, template, scratch, revision, exceptions)
            else:
                policy, policy_revision = fetch_policy(scratch)
                if option != '--sources-only':
                    run(['bash', str(scratch / 'check-pin.sh'), revision])
                if option != '--pin-only':
                    check_sources(root, cfg, scratch, revision, exceptions, policy, policy_revision)
                if command != 'check':
                    if option == '--fixtures-only':
                        if not cfg.get('fixtures'):
                            raise Error('no fixtures declared in contracts.json')
                        expected = read_fixtures(cfg, scratch, revision)
                        actual = current_fixtures(root, cfg)
                    else:
                        expected = prepare(root, cfg, template, scratch, revision)
                        actual = current(root, cfg)
                    if command == 'bump':
                        cfg['commit'] = revision
                        expected['contracts.json'] = (json.dumps(cfg, indent=2) + '\n').encode()
                    install(root, expected, actual)
    except (Error, OSError) as e:
        raise Error(f'{e}\nRepair from the consumer root: {cfg.get("repair", "bash Scripts/contracts.sh generate")}') from None
    print(f'contracts {command}{" " + option if option.startswith("--") else ""} succeeded at {revision}')


if __name__ == '__main__':
    try:
        main()
    except (Error, OSError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        sys.exit(1)
