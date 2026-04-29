# TODO

## Before v0.1.0

- [ ] Add `git-shield` backwards-compat sections to allow old config formats.

## Post v0.1.0

- [x] Cache scan results by git tree/blob hash.
- [x] Timing output and max runtime guard. (progress spinner added)
- [x] Parallel file scanning. (secrets scanning parallelized with ThreadPoolExecutor)
- [x] Optional GLiNER / HF backends for faster CPU/CUDA PII. (`--backend gliner`)
- [x] Windows/WSL support testing. (WSL confirmed working, native Windows not supported)
- [x] Automated release workflow. (GitHub Actions release.yml)
- [x] Install `gitleaks` / `opf` via the tool itself where possible. (`doctor --install`, `bootstrap --install-deps`)
