This library provides an implementation of the [rpm]'s [pgp
interface] using [Sequoia].

  [rpm]: https://github.com/rpm-software-management/rpm
  [pgp interface]: https://github.com/rpm-software-management/rpm/blob/master/include/rpm/rpmpgp.h
  [Sequoia]: https://sequoia-pgp.org

# Building

To build, you need [rustc], cargo and [nettle-devel], which is the
cryptographic library, which Sequoia uses by default.

  [rustc]: https://packages.fedoraproject.org/pkgs/rust/rust/
  [nettle-devel]: https://packages.fedoraproject.org/pkgs/nettle/nettle-devel

Here's how to build rpm-sequoia and a version of rpm that uses it:

```
$ mkdir /tmp/rpm
$ cd /tmp/rpm
$ git clone git@gitlab.com:sequoia-pgp/rpm-sequoia.git
Cloning into 'rpm-sequoia'...
done.
$ cd rpm-sequoia
$ PREFIX=/usr cargo build --release && cargo test --release
    Updating crates.io index
...
test result: ok. ...
$ cd /tmp/rpm
$ git clone git@github.com:rpm-software-management/rpm.git
Cloning into 'rpm'...
done.
$ cd rpm
$ autoreconf -fis
...
$ mkdir b
$ cd b
$ export PKG_CONFIG_PATH=/tmp/rpm/rpm-sequoia/target/release
$ export LD_LIBRARY_PATH=/tmp/rpm/rpm-sequoia/target/release
$ ../configure --with-crypto=sequoia
$ make
$ make check
```

The rpm-sequoia artifacts (the .a, .so, and the .pc files) are placed
in the build directory, which, in this case, is
`/tmp/rpm/rpm-sequoia/target/release`.  We also set the `PREFIX`
environment variable when calling `cargo build`.  This is the prefix
that will be used in the generated `rpm-sequoia.pc` file.  It defaults
to `/usr/local`.


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
