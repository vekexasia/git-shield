# TODO

## MVP

- [ ] Parse actual `pre-push` stdin lines: `<local-ref> <local-sha> <remote-ref> <remote-sha>`.
- [ ] For new branches, choose a sensible base (`origin/main` or merge-base).
- [ ] Add a `privacy-prepush install` command that writes `.git/hooks/pre-push`.
- [ ] Add `pre-commit` framework integration for `stages: [pre-push]`.
- [ ] Add fake-OPF integration tests for the CLI.
- [ ] Add config file support (`privacy-prepush.toml`).

## Performance / reliability

- [ ] Detect CUDA availability before running OPF.
- [ ] Policy for no GPU:
  - [ ] fail closed?
  - [ ] skip with warning?
  - [ ] fallback to CPU only under a small-byte threshold?
- [ ] Chunk large diffs by file or byte size.
- [ ] Add max diff size / max runtime limits.
- [ ] Cache scan results by git tree/blob hash if useful.

## Detection policy

- [ ] Decide default blocked labels:
  - [x] `private_email`
  - [x] `private_phone`
  - [x] `private_person`
  - [x] `private_address`
  - [x] `private_url`
  - [x] `private_date`
  - [x] `account_number`
  - [x] `secret`
- [ ] Support repo-specific label policies.
- [ ] Support repo-specific allowlists and ignore paths.
- [ ] Ensure logs never print raw PII.

## Risto integration

- [ ] Add install docs for `risto-menu`.
- [ ] Decide whether this should run globally or only in sensitive repos.
- [ ] Compare against current regex PII pre-commit hook on realistic diffs.
