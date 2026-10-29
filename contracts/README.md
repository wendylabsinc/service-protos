# Frozen compatibility views

`views.json` fixes each view's source-to-import-path map, generation roots and
file-specific naming lint allowances. `baselines/provenance.json` records the
original repository, full commit, original path, Git blob ID and SHA-256 for
every file, plus the descriptor/fixture hashes. Well-known Google types come
from pinned Buf 1.75.0. All other imports are in the recorded graph.

| View | Existing input graph | Files |
| --- | --- | ---: |
| `catalogue` | service-protos master, unchanged root import paths | 80 |
| `cloud-main-shared` | Cloud console shared input, its three exclusions preserved | 77 |
| `cloud-main-local` | Cloud's five local contracts plus two shared imports | 7 |
| `cloud-legacy-shared` | Cloud legacy's pinned shared submodule | 70 |
| `cloud-legacy-dashboard` | Legacy dashboard mirror (preferred over fallback) | 33 |
| `wendyos` | Go/Swift Agent, Cloud and system generation graph, including recording and SensorLink | 79 |
| `companion` | WendyProtos build-plugin graph | 49 |
| `auth` | FabricProto links resolved through Auth's current submodule pin | 7 |
| `pki` | PKI Makefile's selected shared graph | 8 |
| `pki-dev-shim` | PKI's separate existing dev/test certificate shim | 1 |

These 411 entries share identical source bytes internally. Distinct definitions
remain separate, including old Cloud invite and Agent video variants. The root
catalogue's existing source files and all `conformance/` files are unchanged.
Imported variants live under `sources/`, excluded from the root Buf module.
No symlinks or platform-dependent links are used. Do not build `sources/` as a
single module: its intentional name conflicts represent different deployed APIs.

## Build and generate

Use Python 3.13.7 and Buf 1.75.0 (CI pins both). From a clean checkout:

```sh
python scripts/contracts.py check --base <PR-base-commit>
python -m unittest discover -s scripts -p 'test_*.py' -v
python scripts/contracts.py image cloud-main-local /tmp/cloud-main-local.binpb
buf generate /tmp/cloud-main-local.binpb --template /path/to/consumer/buf.gen.yaml
```

`image` builds a Buf image with original import paths and explicit generation
roots. Cloud-local's two shared imports are dependencies, not extra generation
targets. Other views describe the union consumed by a product's generation
passes. Keep each consumer's existing per-pass paths, language package mappings
and pinned plugins when migrating it. Do not generate every language from every
view or combine views that declare different meanings for the same name.

`export <view> <new-directory>` materializes ordinary source files for inspection.
`image` is preferable for generation because it preserves the root/import split.
Temporary materialization is a build product, never an authoritative source copy.

After publication, a consumer checks out exactly its one `contracts.version`
tag in a temporary/cache directory, without submodules, then invokes `image`
from that checkout and generates from the result. The root catalogue also
supports a direct [Buf Git input](https://buf.build/docs/reference/inputs/):

```sh
# Illustrative, only after the approved tag is published:
contract_tag="$(cat contracts.version)"
git clone --depth 1 --branch "$contract_tag" \
  https://github.com/wendylabsinc/service-protos.git /tmp/contracts-source
python /tmp/contracts-source/scripts/contracts.py image companion /tmp/companion.binpb
buf generate /tmp/companion.binpb --template buf.gen.yaml
# Existing root-only consumers can instead use:
buf build "https://github.com/wendylabsinc/service-protos.git#tag=$contract_tag"
```

The consumer migration must validate the pin as one stable SemVer tag and
verify the fetched tag before use. No branch fallback is allowed. Git credentials
must work in a clean process. See [release/access prerequisites](../docs/releases.md).
CI in this repository needs only its checkout token. Source re-audits below need
read access to all recorded private repositories.

## Baseline provenance

Initial capture reads immutable upstream Git objects, writes the original paths
into isolated modules, and builds each original graph with:

```sh
buf build ORIGINAL_GRAPH --exclude-source-info --output BASELINE.binpb
# cloud-main-local additionally selects only the five top-level local roots.
```

The catalogue checker independently materializes the candidate from its source
map and compares it to those images. Tests require byte-identical descriptor
images for every frozen view. Source/import names, options, JSON names, tags,
types and presence are preserved. Signed-method changes get an additional
explicit check because generic schema compatibility is insufficient.

Re-audit provenance against GitHub without touching any source checkout:

```sh
python scripts/verify-provenance.py
```

That command fetches each immutable upstream tree and matches the Git blob hash
of every mapped source byte-for-byte. No developer checkout is used. The initial
audit matched 411 entries across nine upstream commit trees. The first capture
has no stable tag. Its baseline is these descriptors, never the candidate itself.
Future runs derive the stable tag from full Git history and always retain the
initial comparisons. Baseline files are immutable once on the PR base.

## Generation evidence and known source gap

See `consumers.json` for the exact inspected consumer revisions, generation paths
and input roots. Cloud's two local symlinks resolve to `wendy/options.proto` and
`wendycloud/v2/signed_request.proto` in its pinned submodule. Auth's current seven
FabricProto links resolve to its recorded service-protos pin. These links are
resolved to ordinary files here, with shared authoritative bytes deduplicated.

Cloud main's Swift generator also explicitly requires `image_assignment.proto`,
but that file is absent from its pinned service-protos commit. Its presence check
currently stops regeneration before deleting generated files. This catalogue
captures all present shared/local graphs and does **not** invent that missing
contract, drop it from Cloud's generator or claim that full Swift regeneration
passes. Resolving that existing source gap is a prerequisite for the later Cloud
consumer migration. The current Cloud generated sources remain untouched.

Containerd sources and standalone Wendy Lite application protocols are outside
the shared Agent/Cloud graph. SensorLink is included because Agent v2 imports it.
Standalone frozen Core, Go and Swift wrapper repositories were not modified.
