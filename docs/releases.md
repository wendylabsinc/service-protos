# Catalogue releases

> **Historical / superseded draft.** The foundation was rolled back by
> [service-protos #161 — revert: roll back prematurely merged contract foundation](https://github.com/wendylabsinc/service-protos/pull/161).
> The `v0.1.0` tag was deleted on 2026-10-31. It is not a usable input or
> a publication target. The retained release/protection proposal below is
> historical, not an instruction to activate it. See the
> [current source-only approach](../README.md#current-source-only-approach).

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

## Historical initial publication

Konstantin explicitly approved the initial publication before the foundation
was rolled back. That historical approval does not authorize recreating the
deleted tag. The obsolete bootstrap and publishing instructions have been
removed. No release is part of the current source-only work.

For private Git inputs, CI needs read access to service-protos. A consumer's
ordinary repository token does not imply access to this repository. Use a
scoped GitHub App installation token or existing approved read-only credential,
with the normal Git credential helper. Do not put tokens in pins, command URLs
or logs. Authentication failure must stop generation, with no local-copy
fallback.
