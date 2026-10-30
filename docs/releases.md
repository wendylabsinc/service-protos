# Catalogue releases

Initial planned tag: `v0.1.0`. No tag or package is published by this PR or CI.
The same support, additive-compatibility and retirement guarantees apply during
`0.x`. Pre-1.0 versioning does not permit breaking supported APIs.

- Minor releases add compatible fields/methods or a new API package beside old
  packages. Catalogue versions and API package versions are independent.
- Patch releases change documentation or generation metadata without changing
  contracts. A meaning/validation/auth change is not a patch.
- A catalogue major bump never licenses breaking a supported API package and is
  not an automatic runtime incompatibility signal. Compatibility depends on API
  versions/features, not catalogue-major equality.
- Tags are immutable and forward-only. Correct a published catalogue with a new
  forward release, never by moving/deleting a tag. A consumer may revert to a
  previously validated tag while its APIs remain supported. Retired content may
  leave future catalogues only through [approved retirement](compatibility.md#add-within-a-version),
  including the support window, deployed-client evidence and separate review.

The accountable contract and release owner role is unassigned. Ready, merge,
tag publication, packages and deployments remain separate decisions. No release
workflow runs here, and this PR supplies no runtime version header or cutoff gate.

## Prepared protection changes

Read-only inspection on 2026-10-30 returned no repository rulesets and HTTP 404
for master branch protection. Do not infer that organization rules are absent.
The [master](../.github/proposed-rulesets/master.json) and
[tag](../.github/proposed-rulesets/tags.json) JSON files are proposals, not applied
configuration. Review the current rules again before applying them and retain
any existing requirements.

The proposed master rule requires `contracts` from GitHub Actions, current-base
checks, owner review, fresh approval and resolved review threads. The PR author
cannot approve their own PR. Before activating code-owner protection, assign an
eligible owner with repository write access and establish CODEOWNERS coverage.
Each PR needs an eligible CODEOWNER other than its author. An ordinary
review by someone who is not a CODEOWNER cannot satisfy that gate. The latest
push also needs approval from someone other than its pusher. Preserve
established domain-owner coverage when adding owners. Do not add bypasses or
disable review protection to get a merge through.

After that prerequisite and Konstantin's explicit settings approval, from the
merged checkout:

```sh
gh api repos/wendylabsinc/service-protos/rulesets
gh api repos/wendylabsinc/service-protos/branches/master/protection
gh api --method POST repos/wendylabsinc/service-protos/rulesets \
  --input .github/proposed-rulesets/master.json
gh api --method POST repos/wendylabsinc/service-protos/rulesets \
  --input .github/proposed-rulesets/tags.json
```

Tag updates and deletions have no bypass actors. Tag creation remains a manual
owner-authorized action, not delegated to CI. GitHub's
[ruleset rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
define the exact update/deletion and review semantics.

## Initial v0.1.0 bootstrap

Konstantin explicitly approved publishing the initial `v0.1.0` after all three
catalogue pieces merge and pass validation under the current repository
settings. This approval does not include activating the proposed protections.
Until separately approved and applied, tag immutability is policy, not a
GitHub-enforced guarantee. Record the actual protection state with this release.
For future catalogue releases, the normal protection prerequisite remains:
activate and verify the proposed protections only after separate settings
approval and the eligible-CODEOWNER requirement above are satisfied.

## Exact next tag steps (only after explicit publication approval)

1. Merge the deployed-source import, frozen views/checks and ownership/release
   policy in their declared dependency order, with green checks and explicit
   merge approval. Fetch full history and tags, inspect the approved release
   commit and confirm it is on `origin/master` and includes all three pieces.
   Record the current protection state honestly and confirm `v0.1.0` does not
   exist. The initial bootstrap approval above applies to this release only.
2. From a clean worktree, run the following with `APPROVED_MERGE_SHA` and
   `PR_BASE_SHA` set to the actual reviewed commits. Stop on any failure or existing tag. The second SHA
   is the PR base, never the candidate itself.

```sh
(
  set -eu
  release_worktree_status="$(git status --porcelain)"
  test -z "$release_worktree_status"
  git fetch origin master --tags
  git merge-base --is-ancestor "$APPROVED_MERGE_SHA" origin/master
  published_contract_tag="$(git ls-remote --tags origin refs/tags/v0.1.0)"
  test -z "$published_contract_tag"
  git checkout --detach "$APPROVED_MERGE_SHA"
  python3 scripts/contracts.py check --base "$PR_BASE_SHA"
  python3 -m unittest discover -s scripts -p 'test_*.py' -v
  release_worktree_status="$(git status --porcelain)"
  test -z "$release_worktree_status"
  git tag -a v0.1.0 "$APPROVED_MERGE_SHA" -m 'Initial immutable contract catalogue'
  git push origin refs/tags/v0.1.0
)
```

3. Verify the remote tag peels to the approved merge commit and a clean
   authenticated Git checkout can export every view. Record the commit and
   observed protection state in release notes. Do not report proposed rulesets
   as active. Creating a GitHub Release or packages is not
   implicit in the commands above.
4. Only then migrate Cloud main/legacy, WendyOS, Companion, pki-core and Auth in
   their separate PRs. Embedded Core is conditional on its existing WendyOS
   move. Frozen standalone Core/Go/Swift repositories receive no changes.

For private Git inputs, CI needs read access to service-protos. A consumer's
ordinary repository token does not imply access to this repository. Use a
scoped GitHub App installation token or existing approved read-only credential,
with the normal Git credential helper. Do not put tokens in pins, command URLs
or logs. Authentication failure must stop generation, with no local-copy
fallback.
