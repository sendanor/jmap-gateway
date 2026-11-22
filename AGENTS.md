# Repository workflow

- Keep the primary checkout on `develop`.
- Perform every change on a separate branch in its own Git worktree. Use the `codex/` prefix for Codex branches.
- Commit completed work in the feature worktree. Verify it there before integrating the commits into `develop`.
- Update the JMAP feature status table in `README.md` when supported behavior changes.
