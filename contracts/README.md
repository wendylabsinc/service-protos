# Deployed source inventory

This directory collects deployed protobuf source bytes for the shared-contract
migration. It does not change a consumer, select an API variant for generation,
or publish a catalogue release. The existing root sources remain unchanged.

`inventory.json` records 194 distinct local source files: 114 imported snapshots
under `sources/` and 80 identical files already available at the repository root.
Every source has its SHA-256 and original Git blob IDs, repository names, full
commits and paths. The ten named graphs map the 411 inspected import paths to
those shared source files. These graph names are inventory labels, not build
profiles or a supported generation interface.

| Inspected graph | Source/import paths |
| --- | ---: |
| service-protos root catalogue | 80 |
| Cloud main shared input | 77 |
| Cloud main local contracts and two shared imports | 7 |
| Cloud legacy shared input | 70 |
| Cloud legacy dashboard mirror | 33 |
| WendyOS Agent/Cloud/system graph, including recording and SensorLink | 79 |
| Companion WendyProtos | 49 |
| Auth FabricProto | 7 |
| PKI shared graph | 8 |
| PKI's existing separate dev/test certificate shim | 1 |

Identical bytes share a local source file. Existing incompatible definitions
remain separate, including Cloud's local UUID invite contract versus the root
numeric invite contract, and the Agent video variants. No fields, import paths,
JSON names, presence, signed-method options or documented behavior are normalized.

`consumers.json` records the inspected consumer commits, generator paths/hashes
and input selections. Cloud's two local symlinks and Auth's FabricProto symlinks
were resolved through their pinned service-protos commits. The imported snapshots
here are ordinary files. Containerd inputs and standalone Wendy Lite application
protocols are outside this shared graph. SensorLink is included because Agent v2
imports it.

## Verify the import

From this repository, with Python 3.10 or newer:

```sh
python3 scripts/verify-provenance.py
python3 -m unittest discover -s scripts -p 'test_provenance.py' -v
```

The local check verifies source bytes against the recorded SHA-256 and Git blob
IDs, full upstream commit hashes, graph references, and completeness of the
imported file inventory. It does not perform API compatibility checks or certify
a consumer build.

To independently confirm the recorded upstream commits and paths, authenticate
`gh` with read access to the source repositories and run:

```sh
python3 scripts/verify-provenance.py --upstream
```

This read-only audit compares the local Git blob hashes with nine immutable
GitHub commit trees. It covers 332 distinct upstream file records. It needs no
local checkout of any consumer repository. CI uses the offline check so it
requires no additional cross-repository credentials.

The root Buf module excludes `contracts/` so imported definitions do not enter
existing generation. Existing changed-file lint skips only `contracts/sources/`
and verifies those files with the provenance check instead. The existing root
breaking-check configuration remains as on master. Building the root produces
the same descriptor image as before this import. Do not compile all of `sources/`
together: its duplicate identities intentionally preserve divergent deployed APIs.

## Known source gap and landing order

Cloud main's Swift generator requires `image_assignment.proto`, absent from its
pinned service-protos commit. Its existing presence check stops regeneration.
The inventory records that gap, without inventing the contract, dropping it from
Cloud's generator, or claiming full Swift regeneration works. Resolve it before
the later Cloud consumer migration.

This is the mechanical import piece. The next independently reviewed piece
assembles compatibility views and adds strict checks/baselines. Ownership,
compatibility policy and release/tag rules follow separately. Nothing here
requires either later piece to build or land.
