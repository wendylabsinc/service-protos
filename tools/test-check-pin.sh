#!/usr/bin/env bash
# Real Git graph tests; URL rewriting is confined to this test process.
set -euo pipefail
checker="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-pin.sh"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$scratch/gitconfig"
export GIT_TERMINAL_PROMPT=0
mkdir -p "$scratch/disposable" "$scratch/bin"
export TMPDIR="$scratch/disposable"
real_git="$(command -v git)"
export REAL_GIT="$real_git"
source_repo="$scratch/source repo"
url=https://github.com/wendylabsinc/service-protos.git

commit() {
    git -C "$source_repo" -c user.name=Fixture -c user.email=fixture@example.invalid \
        -c commit.gpgsign=false -c core.hooksPath=/dev/null commit --quiet --allow-empty -m "$1"
}
git init --quiet --initial-branch=master "$source_repo"
commit root
root="$(git -C "$source_repo" rev-parse HEAD)"
git -C "$source_repo" checkout --quiet -b merged
commit merged
merged="$(git -C "$source_repo" rev-parse HEAD)"
git -C "$source_repo" checkout --quiet master
commit master
git -C "$source_repo" -c user.name=Fixture -c user.email=fixture@example.invalid \
    -c commit.gpgsign=false -c core.hooksPath=/dev/null merge --quiet --no-ff merged -m merge
master="$(git -C "$source_repo" rev-parse HEAD)"
git -C "$source_repo" checkout --quiet -b branch-only "$root"
commit unmerged
branch_only="$(git -C "$source_repo" rev-parse HEAD)"
git -C "$source_repo" checkout --quiet master
git config --global "url.file://$source_repo.insteadOf" "$url"

count=0
run_check() {
    local expected="$1" diagnostic="$2" status=0
    shift 2
    bash "$checker" "$@" >"$scratch/output" 2>&1 || status=$?
    if [[ "$expected" == pass ]]; then
        if [[ "$status" -ne 0 ]] || ! grep -Fq 'Verified shared contract pin' "$scratch/output"; then
            cat "$scratch/output" >&2
            echo 'FAIL: expected accepted pin' >&2
            exit 1
        fi
    elif [[ "$status" -eq 0 ]] || ! grep -Fq "$diagnostic" "$scratch/output" \
        || grep -Fq 'Verified shared contract pin' "$scratch/output"; then
        cat "$scratch/output" >&2
        echo "FAIL: expected rejection with: $diagnostic" >&2
        exit 1
    fi
    if [[ -n "$(ls -A "$TMPDIR")" ]]; then
        echo 'FAIL: temporary repository was not cleaned up' >&2
        exit 1
    fi
    count=$((count + 1))
    echo "ok $count: $expected ${diagnostic:-pin on master}"
}

# Independent acceptance and rejection assertions over the real merged graph.
run_check pass '' "$merged"
git -C "$source_repo" cat-file -e "$branch_only^{commit}"
run_check fail 'is not an ancestor of service-protos master' "$branch_only"
echo "Negative control: existing branch-only commit $branch_only rejected; merged ancestor $merged accepted"
run_check pass '' "$master"

# A shallow caller with misleading local master cannot influence verification.
git clone --quiet --depth=1 --branch branch-only "file://$source_repo" "$scratch/caller"
git -C "$scratch/caller" branch master
cd "$scratch/caller"
run_check pass '' "$root"
run_check fail 'is not an ancestor of service-protos master' "$branch_only"
caller_refs="$(git show-ref)"
GIT_DIR="$scratch/caller/.git" GIT_WORK_TREE="$scratch/caller" run_check pass '' "$root"
GIT_DIR="$scratch/caller/.git" GIT_WORK_TREE="$scratch/caller" \
    run_check fail 'is not an ancestor of service-protos master' "$branch_only"
if [[ "$(git show-ref)" != "$caller_refs" ]]; then
    echo 'FAIL: checker changed caller refs' >&2
    exit 1
fi

run_check fail 'usage:'
run_check fail 'usage:' "$master" extra
run_check fail 'usage:' master
run_check fail 'usage:' "${master:0:12}"
run_check fail 'usage:' 000000000000000000000000000000000000000g
run_check fail 'usage:' ABCDEF0123456789ABCDEF0123456789ABCDEF01
run_check fail 'could not fetch service-protos master and pinned commit' 0000000000000000000000000000000000000000

git -C "$source_repo" branch -m master other
run_check fail 'could not fetch service-protos master and pinned commit' "$root"
git -C "$source_repo" branch -m other master
git config --global --unset "url.file://$source_repo.insteadOf"
git config --global "url.file://$scratch/unavailable.insteadOf" "$url"
run_check fail 'could not fetch service-protos master and pinned commit' "$root"
git config --global --unset "url.file://$scratch/unavailable.insteadOf"
git config --global "url.file://$source_repo.insteadOf" "$url"

# Only infrastructure error injection is stubbed; graph policy above uses Git.
cat >"$scratch/bin/git" <<'STUB'
#!/usr/bin/env bash
for arg in "$@"; do
    if [[ "$arg" == "${FAIL_GIT_OPERATION:-}" ]]; then
        echo "injected Git failure: $arg" >&2
        exit 73
    fi
done
exec "$REAL_GIT" "$@"
STUB
chmod +x "$scratch/bin/git"
export PATH="$scratch/bin:$PATH"
export FAIL_GIT_OPERATION=init
run_check fail 'could not initialize temporary repository' "$root"
export FAIL_GIT_OPERATION=fetch
run_check fail 'could not fetch service-protos master and pinned commit' "$root"
export FAIL_GIT_OPERATION=merge-base
run_check fail 'ancestry could not be verified' "$root"
unset FAIL_GIT_OPERATION
cat >"$scratch/bin/mktemp" <<'STUB'
#!/usr/bin/env bash
echo 'injected mktemp failure' >&2
exit 73
STUB
chmod +x "$scratch/bin/mktemp"
run_check fail 'could not create temporary repository' "$root"
echo "Passed $count pin checker tests"
