This library provides an implementation of the [rpm]'s [pgp
interface] using [Sequoia].

  [rpm]: https://github.com/rpm-software-management/rpm
  [pgp interface]: https://github.com/rpm-software-management/rpm/blob/master/include/rpm/rpmpgp.h
  [Sequoia]: https://sequoia-pgp.org

# Building

To build, you need [rustc], cargo and [nettle-devel], which is the
cryptographic library, which Sequoia uses by default.

  [rustc]: https://packages.fedoraproject.org/pkgs/rust/rust/
  [nettle-devel]: https://packages.fedoraproject.org/pkgs/nettle/nettle-deve/l

I'm testing with version 1.56.1 of rustc.  As of this writing, Fedora
34, 35 and 36 all ship with at least version 1.58.1.


```
$ mkdir /tmp/rpm
$ cd /tmp/rpm
$ git clone git@gitlab.com:sequoia-pgp/rpm-sequoia.git
Cloning into 'rpm-sequoia'...
done.
$ cd rpm-sequoia
$ cargo build
    Updating crates.io index
...
    Finished dev [unoptimized + debuginfo] target(s) in 48.44s
$ cd /tmp/rpm
$ git clone git@github.com:nwalfield/rpm.git
Cloning into 'rpm'...
done.
$ cd rpm
$ autoreconf -fis
...
$ mkdir b
$ cd b
$ export PKG_CONFIG_PATH=/tmp/rpm/rpm-sequoia/target/debug
$ export LD_LIBRARY_PATH=/tmp/rpm/rpm-sequoia/target/debug
$ ../configure
$ make
$ cd tests
$ make populate_testing
$ make check
```

Or to run one or two tests, do something like:

```
$ T="266 273"; for t in $T; do if ! ../../tests/rpmtests $t; then cat rpmtests.dir/$t/rpmtests.log; fi; done
```

Note: when building or running the test suite, it is essential to make
sure `PKG_CONFIG_PATH` and `LD_LIBRARY_PATH` are set appropriately.

To get tracing output, set RPM_TRACE to 1:

```
$ cd /tmp/rpm/rpm/b/tests
$ export RPM_TRACE=1
$ ../../tests/rpmtests 273
$ cat rpmtests.dir/273/rpmtests.log
...
+pgpDigParamsFree: -> success
+rpmFreeCrypto: entered
+rpmFreeCrypto: -> success
273. rpmsigdig.at:495: 273. rpmsign --addsign (rpmsigdig.at:495): FAILED (rpmsigdig.at:503)
```

To get a release build, run `cargo --release build`.  You'll then need
to adjust the paths appropriately.  Specifically, you'll need to use
`/tmp/rpm/rpm-sequoia/target/release` instead of
`/tmp/rpm/rpm-sequoia/target/debug`.


