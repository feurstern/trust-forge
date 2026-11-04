# Contributing to TrustForge

Thank you for helping! TrustForge is security infrastructure. A wrong "verified" is the worst bug it can have, so the rules below are stricter than many projects'.

## How work is organized

Development proceeds in milestones (see [docs/roadmap.md](docs/roadmap.md)). Each milestone is planned, reviewed and approved before implementation starts, and is only complete when its quality gates pass. Before starting larger work, please open an issue so it can be placed in the right milestone.

## Development setup

1. Install [rustup](https://rustup.rs/). The toolchain pinned in `rust-toolchain.toml` (currently 1.99.1, with rustfmt and clippy) is installed automatically on first use.
2. Run the same checks as CI before opening a pull request:

   ```sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --locked -- -D warnings
   cargo test --workspace --locked
   RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
   cargo deny check        # needs cargo-deny: https://github.com/EmbarkStudios/cargo-deny
   ```

The minimum supported Rust version (MSRV) is `rust-version` in `Cargo.toml` (currently 1.88), and CI checks it. Dependabot does not update `rust-toolchain.toml`, so toolchain upgrades are done by hand in their own pull request.

## Rules for code changes

- **No `unsafe` code.** It is forbidden at the workspace level.
- **Fail closed.** If a check cannot be completed, its result is an error or "not evaluated", never a pass. Unimplemented features return an explicit "unsupported" result.
- **No placeholders in verification logic.** `todo!()`, `unimplemented!()` and mock verification results must never reach production code (clippy enforces the first two).
- **No panics on untrusted input.** Every artifact, manifest, provenance document, report and build output is untrusted. Use typed errors (`thiserror` in libraries) instead of `unwrap`/`expect`.
- **Tests come with the change.** New behavior needs unit tests. Security-relevant behavior also needs a regression test that would fail if the protection were removed.
- **Tests must not need the network.** Tests that need Docker or network access are opt-in and clearly marked.
- **Deterministic output.** The same inputs must produce byte-identical machine-readable output: sorted collections, no timestamps unless requested.
- **No new dependencies without justification.** Explain in the pull request what the crate does for us, its maintenance status, license, dependency footprint and MSRV, and the alternatives you considered. `cargo deny check` must pass.
- **Keep the docs honest.** Changes to security-sensitive behavior must update [docs/threat-model.md](docs/threat-model.md). Never mark a standard as supported in [docs/standards.md](docs/standards.md) until it is implemented and tested, and never describe a guarantee the code cannot demonstrate.

## Pull requests

- Keep each pull request focused on one logical change.
- Describe what changed, why, and how you tested it, including the actual test output for anything non-obvious.
- Add an entry under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) for user-visible changes.

## Reporting security issues

Do not open public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md).

## License

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed under the MIT and Apache-2.0 licenses, without any additional terms or conditions.
