This library provides an implementation of the [rpm]'s [pgp
interface] using [Sequoia].

  [rpm]: https://github.com/rpm-software-management/rpm
  [pgp interface]: https://github.com/rpm-software-management/rpm/blob/master/include/rpm/rpmpgp.h
  [Sequoia]: https://sequoia-pgp.org

# Configuration

This library's [crypto policy] can be customized.  It finds the
configuration file by checking the following in turn:

  - the `RPM_SEQUOIA_CRYPTO_POLICY` environment variable,
  - `/etc/crypto-policies/back-ends/rpm-sequoia.config`,
  - the `SEQUOIA_CRYPTO_POLICY` environment variable, and finally,
  - `/etc/crypto-policies/back-ends/sequoia.config`.

Only the first configuration file that is present is used.  If an
environment is set to the empty string, then an empty configuration
file is used.  That is, the default policy is used.

Thus, if `RPM_SEQUOIA_CRYPTO_POLICY` is not set, and
`/etc/crypto-policies/back-ends/rpm-sequoia.config`, the latter will
be used.  In this case, `SEQUOIA_CRYPTO_POLICY` and
`/etc/crypto-policies/back-ends/sequoia.config` will be completely
ignored.

Refer to the [Fedora Crypto Policy] project for information about the
crypto policy.

  [crypto policy]: https://docs.rs/sequoia-policy-config/latest/sequoia_policy_config/
  [Sequoia's default policy]: https://docs.sequoia-pgp.org/sequoia_openpgp/policy/struct.StandardPolicy.html
  [Fedora Crypto Policy]: https://gitlab.com/redhat-crypto/fedora-crypto-policies/


# Building

To build, you need [rustc] (version 1.85 or later), cargo, and
[nettle-devel], which is the cryptographic library that Sequoia uses
by default.

  [rustc]: https://packages.fedoraproject.org/pkgs/rust/rust/
  [nettle-devel]: https://packages.fedoraproject.org/pkgs/nettle/nettle-devel

```
$ sudo dnf install cargo rustc clang pkg-config nettle-devel
$ mkdir /tmp/rpm
$ cd /tmp/rpm
$ git clone https://github.com/rpm-software-management/rpm-sequoia.git
Cloning into 'rpm-sequoia'...
done.
$ cd rpm-sequoia
$ PREFIX=/usr LIBDIR="\${prefix}/lib64" \
  cargo build --release && cargo test --release
    Updating crates.io index
...
test result: ok. ...
```

To use a different cryptographic backend, you need to disable the
default backend, and select your preferred backend.  For instance, to
use Sequoia's OpenSSL backend, you would compile `rpm-sequoia` as
follows:

```
$ cargo build --release --no-default-features --features crypto-openssl
```

See [`sequoia-openpgp`'s README] for the list of currently supported
cryptographic backends.

  [`sequoia-openpgp`'s README]: https://gitlab.com/sequoia-pgp/sequoia#features

The rpm-sequoia artifacts (the .a, .so, and the .pc files) are placed
in the build directory, which, in this case, is
`/tmp/rpm/rpm-sequoia/target/release`.

We also set two environment variables when calling `cargo build`:

* `PREFIX` is the prefix that will be used in the generated
  `rpm-sequoia.pc` file. It defaults to `/usr/local`.

* `LIBDIR` is the installed library path listed in the generated
  metadata. It can be an absolute path or one based on `${prefix}`,
  and defaults to `${prefix}/lib`.

# Testing

`rpm-sequoia` has a minimal test suite.  Testing is instead done via
`rpm`'s test suite.

# rpm 4.20

As of version 4.20, `rpm` uses containers to run its test suite.  The
simplest solution is to build a container with the `rpm` test suite,
copy `rpm-sequoia` on top of that (for example in another container
layer), run `ldconfig`, and then run the tests, like so:

```
$ cd /tmp/rpm
$ git clone https://github.com/rpm-software-management/rpm.git
Cloning into 'rpm'...
done.
$ cd rpm/tests
$ podman build --target full -t rpm-tests -f Dockerfile ..
$ cd /tmp/rpm/rpm-sequoia
$ podman build -t rpm-tests-sequoia -f tests/Dockerfile .
$ podman run --privileged -it --rm --read-only --tmpfs /tmp -v /tmp/rpm/rpm/:/srv:z  --workdir /srv -e ROOTLESS=1 rpm-tests-sequoia rpmtests -k OpenPGP -k signature -k rpmkeys -k digest
```

To get tracing output, set the `RPM_TRACE` environment variable
to 1. This can be passed by adding `-e RPM_TRACE=1` to the last
command, like so:

```
$ podman run --privileged -it --rm --read-only --tmpfs /tmp -v /tmp/rpm/rpm/:/srv:z  --workdir /srv -e ROOTLESS=1 -e RPM_TRACE=1 rpm-tests-sequoia rpmtests -k OpenPGP -k signature -k rpmkeys -k digest
```

If a tests fails, its log will be saved to
`/tmp/rpm/rpm/rpmtests.dir/xxx/rpmtests.log` where `xxx` is the test's
number.  The entire run's log is saved to `/tmp/rpm/rpm/rpmtests.log`.
Note: these are exposed to the file system due to how we run `podman`.

# For rpm 4.18

To build and test rpm-sequoia for rpm version 4.18, do:

```
$ cd /tmp/rpm
$ git clone git@github.com:rpm-software-management/rpm.git
Cloning into 'rpm'...
done.
$ cd rpm
$ git checkout rpm-4.18.1-release
Switched to a new branch 'rpm-4.18.1-release'
$ sudo dnf install automake autoconf gettext-devel libtool tar zlib-devel file-devel libarchive-devel popt-devel sqlite-devel lua-devel fakechroot
$ autoreconf -fis
...
$ mkdir b
$ cd b
$ export PKG_CONFIG_PATH=/tmp/rpm/rpm-sequoia/target/release
$ export LD_LIBRARY_PATH=/tmp/rpm/rpm-sequoia/target/release
$ ../configure --prefix=/ --with-crypto=sequoia
$ make
$ make check
```

# Symbols test without Rust toolchain

To run the symbols test binary without having a Rust toolchain installed, set an environment 
variable called `TEST_DONT_BUILD_LIB` with any value. This of course requires you to build 
the library before the test would be executed.

# Cross Compiling

In a cross-compilation context (e.g., Yocto), Cargo's default paths
(`OUT_DIR` and `CARGO_MANIFEST_DIR`) may not be valid when the test
suite is run.  To run the test suite anyway, you can set
`FORCE_RUNTIME_PATH_LIB` and `FORCE_RUNTIME_PATH_SRC` to override
these paths.
