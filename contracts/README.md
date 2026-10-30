# Frozen compatibility views

`inventory.json` is the immutable source authority from the deployed-source
import: 194 distinct files, 332 upstream records and 411 graph/import entries.
`views.json` selects those sources at their original import paths and fixes
generation roots and file-specific naming lint allowances. Intentional name
conflicts remain isolated, including Cloud invite and Agent video variants.
No schema content, consumer input or runtime behavior changes here.
The source audit requires full immutable upstream commit hashes.

| View | Existing input graph | Files |
| --- | --- | ---: |
| `catalogue` | service-protos root, with existing import paths | 80 |
| `cloud-main-shared` | Cloud console shared input, preserving its three exclusions | 77 |
| `cloud-main-local` | Five local contracts and two shared dependencies | 7 |
| `cloud-legacy-shared` | Legacy Cloud's pinned shared submodule | 70 |
| `cloud-legacy-dashboard` | Legacy dashboard mirror, preferred over fallback | 33 |
| `wendyos` | Agent/Cloud/system graph, including recording and SensorLink | 79 |
| `companion` | WendyProtos build-plugin graph | 49 |
| `auth` | FabricProto links resolved through Auth's submodule pin | 7 |
| `pki` | PKI Makefile's selected shared graph | 8 |
| `pki-dev-shim` | PKI's separate dev/test certificate shim | 1 |

Imported variants under `sources/` are ordinary files, excluded from root Buf
generation. Do not compile that directory as one module. Identical bytes share
one source until a canonical edit needs an unchanged snapshot (see below).
Well-known Google types come from pinned Buf 1.75.0.

## Build, generate and check

Use Python 3.15.2 and Buf 1.75.0, matching CI. From a full checkout with tags:

```sh
python3 scripts/contracts.py check --base <PR-base-commit>
python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/contracts.py image cloud-main-local /tmp/cloud-main-local.binpb
buf generate /tmp/cloud-main-local.binpb --template /path/to/consumer/buf.gen.yaml
```

`image` preserves original import paths and generation roots. Cloud-local's two
shared imports are dependencies, not extra generation targets. Other views
describe a union of existing generation passes. Preserve each consumer's
per-pass paths, language package mappings and pinned plugins when migrating it.
Do not combine views with conflicting identities. `export <view> <new-directory>`
materializes ordinary files for inspection; those files are temporary outputs.
The root catalogue still supports ordinary Buf Git inputs.

Every PR builds and lints all views on Linux and Windows, with strict `FILE`
breaking checks against both the independent PR base and latest numeric stable
`vMAJOR.MINOR.PATCH` tag. Fetch full history and tags. Until the first release,
captured descriptors supply the release baseline. Initial captures remain
checked after later tags appear. No breaking exemptions are allowed. Existing
file-specific naming lint allowances preserve published names.

Signed-method options are checked separately. Tests deliberately break request
types, enums, signing options, graph selection, configuration, provenance and
fixtures. Existing Go conformance verifiers run alongside these checks. Schema
checks do not prove runtime behavior compatibility or a complete consumer build.

## Preserve provenance while maintaining canonical APIs

The `catalogue` view can evolve compatibly. Its existing files stay at their
root import paths. Add new root files to its `files` and `roots` selections and
keep the original selections. Every catalogue file must be a generation root
so compatibility checks cannot omit a newly added API. Frozen views retain
their original bytes and generation roots. An additive edit to a file shared
with a frozen view follows this normal maintenance path:

1. Before editing a captured root file such as `users.proto`, copy its original
   bytes to `contracts/sources/captured/users.proto`. Use the original captured
   bytes, even if the canonical file has already evolved. This deterministic
   path preserves the existing inventory record without rewriting it.
2. Point every affected **frozen** view's `files` entry at that captured copy,
   keeping its import-path key unchanged. Keep the catalogue entry at the root
   file. The frozen images must remain byte-identical to their captures.
3. Make the compatible canonical addition and run the full check and tests.
   Imported snapshots, inventory hashes and descriptor baselines stay unchanged.

Even a root file used only by the catalogue needs its historical copy when its
captured bytes change, so the audit can still verify every original source.
The verifier checks all retained copies against original SHA-256 and Git blob
IDs. Arbitrary extra copies, forged historical bytes, changed imported snapshots
and incompatible canonical edits fail. A preserved copy does not exempt the
canonical API from strict comparison with either baseline. The test suite proves
this maintenance path with an additive field while checking frozen images.

## Independent capture and audit

`baselines/*.binpb` were captured from original upstream graphs with pinned Buf,
original import paths and `--exclude-source-info`. `baselines/provenance.json`
holds descriptor hashes, generation/lint selections, fixture hashes and the
inventory digest; it does not duplicate the inventory's source/origin authority.
Cloud-local's capture selects its five top-level roots. Tests rebuild the frozen
graphs and require identical descriptor hashes. Capture evidence and inventory
become immutable against the PR base once landed.

The checker and captures were ported from committed implementation
`d0e18be970d5f759d68bceb4d83aa1ca7a9efd26`, preserving its original descriptor
bytes and adapting source validation to the independently usable import audit.
To audit local historical bytes, or additionally recheck nine immutable GitHub
trees with `gh` read access to the recorded private repositories:

```sh
python3 scripts/verify-provenance.py
python3 scripts/verify-provenance.py --upstream
```

CI uses the offline audit and needs only its checkout token. `consumers.json`
records inspected consumer revisions, generator paths/hashes and input roots.
Cloud and Auth symlinks were resolved through their recorded submodule pins.
Standalone frozen Core, Go and Swift wrapper repositories remain untouched.

## Known source gap

Cloud main's Swift generator requires `image_assignment.proto`, absent from its
pinned service-protos commit. Its existing presence check stops regeneration.
Resolve that gap before the later consumer migration; this catalogue neither
invents that contract nor claims full Cloud Swift regeneration passes.
Containerd inputs and standalone Wendy Lite application protocols are outside
this shared graph. SensorLink is included because Agent v2 imports it.

Ownership, compatibility policy and release/tag procedures follow separately.
These views and checks work with the import predecessor alone, without that
later policy work. No tag or consumer migration is published by this change.
