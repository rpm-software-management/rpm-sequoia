This is a checklist for doing releases.

  1. Start from `origin/main`, create a branch `staging`.
  1. Switch to the branch.
  1. Bump the version in `Cargo.toml` to `XXX`.
  1. Bump the version in `README.md` to `XXX`.
  1. Run `cargo check` (this implicitly updates `Cargo.lock`).
  1. Update dependencies and run tests.
     - Use the exact Rust toolchain version of the current Sequoia
       MSRV (refer to `Cargo.toml`): `rustup default 1.xx`
     - Run `cargo update` to update the dependencies. If some
       dependency is updated and breaks due to our MSRV, find a good
       version of that dependency and select it using e.g. `cargo
       update -p backtrace --precise 3.46`.
     - Run `cargo build && cargo check`
  1. Commit changes to `Cargo.toml` and `Cargo.lock`.
  1. Make a commit with the message `Release XXX.`.
     - Push to github, and create a merge request.  Don't auto merge!!!
  1. Make sure `cargo publish` works:
     - `mkdir -p /tmp/sequoia-staging`
     - `cd /tmp/sequoia-staging`
     - `git clone git@github.com:rpm-software-management/rpm-sequoia.git`
     - `cd rpm-sequoia`
     - `git checkout origin/staging`
     - `cargo publish --features crypto-nettle --dry-run`
  1. Wait until CI and `cargo publish ... --dry-run` are
     successful. In case of errors, correct them, and restart.
  1. Merge the merge request.
  1. Run `cargo publish --features crypto-nettle`.
  1. Make a tag `vXXX` with the message `Release XXX.` signed with an
     offline-key, which has been certified by our
     `openpgp-ca@sequoia-pgp.org` key.
  1. Push the signed tag `vXXX`.

