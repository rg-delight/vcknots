# Branch and Submodule Lifecycle

This repository is being edited as a Git submodule inside the NICE wallet repository worktree.

## Current Branches

Parent repository:

- Path: `/mnt/c/Users/inain/.codex/worktrees/8d6a/delight-wg-nice-expt-wallet`
- Branch: `codex/issue-41-vcknots-harness-research`
- The parent repository records only the VCKnots submodule commit SHA, not the VCKnots branch name.

VCKnots submodule:

- Path: `/mnt/c/Users/inain/.codex/worktrees/8d6a/delight-wg-nice-expt-wallet/docs/references/vcknots`
- Branch: `codex/issue-41-oidf-harness-spike`
- Remote URL in the parent `.gitmodules`: `https://github.com/rg-delight/vcknots.git`

## Mental Model

The parent worktree and the submodule are two Git repositories with two separate branches.

The parent commit pins a submodule SHA. When someone checks out the parent branch and runs `git submodule update --init --recursive`, Git checks out that exact VCKnots commit, usually in detached-HEAD mode. It does not automatically recreate or switch to the VCKnots topic branch.

The VCKnots branch is still useful because it is where the submodule commits should be pushed and reviewed. The parent branch is useful because it records which VCKnots commit the NICE wallet repo expects.

## Expected Lifecycle

1. Work in the VCKnots submodule branch first.

   ```bash
   cd docs/references/vcknots
   git switch codex/issue-41-oidf-harness-spike
   ```

2. Commit VCKnots changes inside the submodule.

   ```bash
   git add conformance/oidf
   git commit -m "test: add wallet final conformance targets"
   ```

3. Return to the parent repository and commit the updated submodule pointer.

   ```bash
   cd ../../..
   git add docs/references/vcknots
   git commit -m "docs: record VCKnots conformance pointer"
   ```

4. Push the VCKnots branch before or together with the parent branch.

   The parent branch can point at a submodule commit that only exists locally, but other people cannot fetch that state. For collaboration, the submodule commit must exist on `rg-delight/vcknots` before the parent branch/PR is useful to others.

5. After the VCKnots branch is merged upstream, update the parent branch if the final SHA changed.

   If the submodule PR is squashed or rebased, the parent repo must advance `docs/references/vcknots` to the merged SHA and commit that pointer change.

## Common Failure Modes

- Parent is clean but submodule has uncommitted changes: commit inside `docs/references/vcknots` first.
- Submodule branch is pushed but parent pointer is not committed: other users will still get the old VCKnots commit.
- Parent pointer is committed but submodule branch is not pushed: other users cannot fetch the pinned commit.
- Running `git submodule update` from the parent can detach the submodule HEAD. Switch back to `codex/issue-41-oidf-harness-spike` before continuing VCKnots work.

## Current Commits

- VCKnots submodule commit: this documentation commit; use `git log --oneline -1` in the submodule for the exact SHA.
- Parent pointer/documentation commit: pending parent pointer update after this submodule commit.

Revision note (2026-05-13): Added to make the parent-worktree plus VCKnots-submodule branch lifecycle explicit before protocol implementation work starts.
