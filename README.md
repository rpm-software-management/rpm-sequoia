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

To build, you need [rustc] (version 1.73 or later), cargo, and
[nettle-devel], which is the cryptographic library that Sequoia uses
by default.

  [rustc]: https://packages.fedoraproject.org/pkgs/rust/rust/
  [nettle-devel]: https://packages.fedoraproject.org/pkgs/nettle/nettle-devel

Here's how to build rpm-sequoia and a version of rpm that uses it:

```
$ sudo dnf install cargo rustc clang pkg-config nettle-devel
$ mkdir /tmp/rpm
$ cd /tmp/rpm
$ git clone git@github.com:rpm-software-management/rpm-sequoia.git
Cloning into 'rpm-sequoia'...
done.
$ cd rpm-sequoia
$ PREFIX=/usr LIBDIR="\${prefix}/lib64" \
  cargo build --release && cargo test --release
    Updating crates.io index
...
test result: ok. ...
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

Note: this builds version 4.18 of `rpm`, which is the current stable
release of `rpm`.  The current development branch of `rpm` has
switched to using `cmake` instead of `autoconf`.  Please refer to
[rpm's `INSTALL`] file for how to build `master`.

  [rpm's `INSTALL`]: https://github.com/rpm-software-management/rpm/blob/master/INSTALL

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


To run just one or two tests, do something like the following:

Note: when building or running the test suite, it is essential to make
sure `PKG_CONFIG_PATH` and `LD_LIBRARY_PATH` are set appropriately (as
in the above transcript).

```
$ cd /tmp/rpm/rpm/b/tests
$ export PKG_CONFIG_PATH=/tmp/rpm/rpm-sequoia/target/release
$ export LD_LIBRARY_PATH=/tmp/rpm/rpm-sequoia/target/release
$ make populate_testing
$ T="266 273"; for t in $T; do if ! ../../tests/rpmtests $t; then cat rpmtests.dir/$t/rpmtests.log; fi; done
```

To get tracing output, set RPM_TRACE to 1:

```
$ cd /tmp/rpm/rpm/b/tests
$ export PKG_CONFIG_PATH=/tmp/rpm/rpm-sequoia/target/release
$ export LD_LIBRARY_PATH=/tmp/rpm/rpm-sequoia/target/release
$ make populate_testing
$ export RPM_TRACE=1
$ ../../tests/rpmtests 273
$ cat rpmtests.dir/273/rpmtests.log
...
+pgpDigParamsFree: -> success
+rpmFreeCrypto: entered
+rpmFreeCrypto: -> success
273. rpmsigdig.at:495: 273. rpmsign --addsign (rpmsigdig.at:495): FAILED (rpmsigdig.at:503)
...
```
