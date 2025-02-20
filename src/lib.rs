//! An implementation of RPM's OpenPGP interface.
//!
//! This library provides an implementation of [RPM's OpenPGP
//! interface](https://github.com/rpm-software-management/rpm/blob/master/include/rpm/rpmpgp.h).
//!
//! **You should not link to this library directly**.
//!
//! If you are looking for an OpenPGP interface, consider using
//! [Sequoia], which this library is based on.  If you want to use
//! RPM's OpenPGP interface, which you should only do if you are
//! interacting with RPM, then you should link against [RPM], which
//! reexports this interface.
//!
//! [Sequoia]: https://gitlab.com/sequoia-pgp/sequoia
//! [RPM]: http://rpm.org
//!
//! If you are investigating a bug in this library, set the
//! `RPM_TRACE` environment variable to 1 to get a verbose trace of
//! the library's execution:
//!
//! ```sh
//! $ LD_LIBRARY_PATH=/tmp/rpm-sequoia/release RPM_TRACE=1 ./rpmkeys \
//!   --import ../tests/data/keys/CVE-2021-3521-badbind.asc
//! _rpmInitCrypto: entered
//! _rpmInitCrypto: -> success
//! _pgpParsePkts: entered
//! ...
//! ```
//!
//! # Policy
//!
//! When Sequoia evaluates the validity of an object (e.g., a
//! cryptographic signature) it consults a policy.  The policy is user
//! defined.  This library uses [Sequoia's standard policy].
//!
//! [Sequoia's standard policy]: https://docs.sequoia-pgp.org/sequoia_openpgp/policy/struct.StandardPolicy.html
//!
//! Sequoia's standard policy allows self-signatures (i.e., the
//! signatures that bind a User ID or subkey to a certificate) made
//! with SHA-1 until February 2023.  It completely disallows data
//! signatures made with SHA-1.  The reason for this is that SHA-1
//! collision resistance is broken, but its second pre-image
//! resistance is still okay.
//!
//! As an added protection, Sequoia uses [SHA-1 collision detection],
//! which is a variant of SHA-1, which mitigates known attacks against
//! SHA-1.  SHA-1 CD has a very low [false positive rate] (2^-90) so
//! it can be treated as a drop-in, fully compatible replacement for
//! SHA-1.
//!
//! [SHA-1 collision detection]: https://github.com/cr-marcstevens/sha1collisiondetection
//! [false positive rate]: https://github.com/cr-marcstevens/sha1collisiondetection#about
//!
//! # Configuration File
//!
//! This library reads the [crypto policy configuration] in
//! `/etc/crypto-policies/back-ends/sequoia.config`.  If that file
//! doesn't exist, it tries
//! `/usr/share/crypto-policies/back-ends/rpm-sequoia.config`.  This
//! can be overridden using the `SEQUOIA_CRYPTO_POLICY` environment
//! variable.  If set to the empty string, then no crypto policy will
//! be read and instead [Sequoia's default policy] will be used.
//!
//! Refer to the [Fedora Crypto Policy] project for information about
//! the crypto policy.
//!
//! [crypto policy configuration]: https://docs.rs/sequoia-policy-config/latest/sequoia_policy_config/
//! [Sequoia's default policy]: https://docs.sequoia-pgp.org/sequoia_openpgp/policy/struct.StandardPolicy.html
//! [Fedora Crypto Policy]: https://gitlab.com/redhat-crypto/fedora-crypto-policies/
use std::env;
use std::ffi::{
    CString,
};
use std::fmt::Debug;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{
    Duration,
    SystemTime,
    UNIX_EPOCH,
};

#[allow(unused_imports)]
use anyhow::Context;

use libc::{
    c_char,
    c_int,
    c_uint,
    c_void,
    size_t,
};

use chrono::{
    DateTime,
    Utc,
};

use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::Cert;
use openpgp::cert::prelude::*;
use openpgp::Fingerprint;
use openpgp::packet::key::{
    PublicParts,
};
use openpgp::packet::{
    Packet,
    Signature,
    Tag,
};
use openpgp::parse::{
    PacketParser,
    PacketParserResult,
    PacketParserBuilder,
    Dearmor,
};
use openpgp::parse::Parse;
use openpgp::policy::{
    NullPolicy,
    StandardPolicy,
    Policy,
};
use openpgp::serialize::SerializeInto;
use openpgp::types::RevocationStatus;

use openpgp::parse::buffered_reader;

#[macro_use] mod log;
#[macro_use] mod ffi;
#[macro_use] pub mod rpm;
use rpm::{
    Error,
    ErrorCode,
    PgpArmor,
    PgpArmorError,
    Result,
};
pub mod digest;

lazy_static::lazy_static! {
    static ref P: RwLock<StandardPolicy<'static>> = RwLock::new(StandardPolicy::new());
}
const NP: &NullPolicy = unsafe {
    &NullPolicy::new()
};

// Set according to the RPM_TRACE environment variable (enabled if
// non-zero), or if we are built in debug mode.
lazy_static::lazy_static! {
    static ref TRACE: bool = {
        if let Ok(v) = env::var("RPM_TRACE") {
            let v: isize = v.parse().unwrap_or(1);
            v != 0
        } else {
            false
        }
    };
}

/// Prints the error and causes, if any.
pub fn print_error_chain(err: &anyhow::Error) {
    eprintln!("           {}", err);
    err.chain().skip(1).for_each(|cause| eprintln!("  because: {}", cause));
}

// Sometimes the same error cascades, e.g.:
//
// ```
// $ sq-wot --time 20230110T0406   --keyring sha1.pgp path B5FA089BA76FE3E17DC11660960E53286738F94C 231BC4AB9D8CAB86D1622CE02C0CE554998EECDB FABA8485B2D4D5BF1582AA963A8115E774FA9852 "<carol@example.org>"
// [ ] FABA8485B2D4D5BF1582AA963A8115E774FA9852 <carol@example.org>: not authenticated (0%)
//   ◯ B5FA089BA76FE3E17DC11660960E53286738F94C ("<alice@example.org>")
//   │   No adequate certification found.
//   │   No binding signature at time 2023-01-10T04:06:00Z
//   │     No binding signature at time 2023-01-10T04:06:00Z
//   │     No binding signature at time 2023-01-10T04:06:00Z
// ...
// ```
//
// Although technically correct, it's just noise.  Compress them.
fn error_chain(err: &anyhow::Error) -> Vec<String> {
    let mut errs = std::iter::once(err.to_string())
        .chain(err.chain().map(|source| source.to_string()))
        .collect::<Vec<String>>();
    errs.dedup();
    errs
}

// Generate macros for working with lints.
//
// Note: $dollar is a hack, which we use because nested macros with
// repetitions don't currently work.  See:
// https://github.com/rust-lang/rust/pull/95860
macro_rules! linter {
    ($dollar:tt, $lints:ident) => {
        // A helper macro to add a lint.
        //
        // If `$err` is `None`, `$msg` is turned into an `anyhow::Error` and
        // appended to `lints`.
        //
        // If `$err` is `Some`, `$msg` is added as context to `$err` and is
        // then appended to `lints`.
        macro_rules! add_lint {
            ($err:expr, $msg:expr $dollar(, $args:expr)*) => {{
                let err: Option<anyhow::Error> = $err;
                let msg = format!("{}", format_args!($msg $dollar(, $args)*));
                let err = if let Some(err) = err {
                    err.context(msg)
                } else {
                    anyhow::anyhow!(msg)
                };
                $lints.push(err);
            }};
        }

        // A helper to return an error.
        //
        // This adds a lint using `lint!` and then returns
        // `Error::Fail($msg)`.
        macro_rules! return_err {
            ($err:expr, $msg:expr $dollar(, $args:expr)*) => {{
                add_lint!($err, $msg $dollar(, $args)*);
                return Err(Error::Fail(
                    format!("{}", format_args!($msg $dollar(, $args)*))));
            }};
        }
    }
}

// By default we prefer this environment variable and this file, but
// if that is not present, we fallback to the default configuration.
const RPM_SEQUOIA_CONFIG_ENV: &'static str
    = "RPM_SEQUOIA_CRYPTO_POLICY";
const RPM_SEQUOIA_CONFIG: &[&str] = &[
    "/etc/crypto-policies/back-ends/rpm-sequoia.config",
    "/usr/share/crypto-policies/back-ends/rpm-sequoia.config",
];

ffi!(
/// int rpmInitCrypto(void)
fn _rpmInitCrypto() -> Binary {
    // XXX: Remove this once v4 signatures are ubiquitous.
    //
    // Unfortunately, much of the rpm ecosystem is still (2022)
    // generating v3 signatures.  As they aren't completely broken,
    // accept them by default, but still let them be overridden by the
    // system policy.
    //
    // See https://bugzilla.redhat.com/show_bug.cgi?id=2141686
    let mut p = openpgp::policy::StandardPolicy::new();
    p.accept_packet_tag_version(openpgp::packet::Tag::Signature, 3);

    let mut p = sequoia_policy_config::ConfiguredStandardPolicy
        ::from_policy(p);

    // We can only specify a single file to
    // `ConfiguredStandardPolicy::parse_config_file`.  We work around
    // it (for now) by taking the first file that exists.
    let rpm_sequoia_config = RPM_SEQUOIA_CONFIG
	.iter()
	.find(|path| {
	    PathBuf::from(path).exists()
	})
	.unwrap_or(&RPM_SEQUOIA_CONFIG[0]);

    match p.parse_config(RPM_SEQUOIA_CONFIG_ENV,
                         rpm_sequoia_config)
    {
        Ok(false) => {
            // Fallback to the default configuration.
            if let Err(err) = p.parse_default_config() {
                print_error_chain(&err);
                return Err(err.into());
            }
        }
        Ok(true) => (),
        Err(err) => {
            print_error_chain(&err);
            return Err(err.into());
        }
    }

    *crate::P.write().unwrap() = p.build();

    Ok(())
});

ffi!(
/// int rpmFreeCrypto(void)
fn _rpmFreeCrypto() -> Binary {
    Ok(())
});

// These are still implemented in C due to internationalization, and
// to avoid translating the string tables, which is a fair amount of
// error prone work, and doesn't improve safety.
//
// stub!(pgpValString);
// stub!(pgpIdentItem);

// This is implemented in C: it is just a wrapper around pgpParsePkts,
// which uses some internal rpm functions.
//
// stub!(pgpReadPkts);

/// An OpenPGP object.
///
/// This data structure can hold either a signature, a certificate, or
/// a subkey.
enum PgpDigParamsObj {
    Cert(Cert),
    Subkey(Cert, Fingerprint),
    Signature(Signature),
}

pub struct PgpDigParams {
    obj: PgpDigParamsObj,
    signid: [u8; 8],
    userid: Option<CString>,
}

impl PgpDigParams {
    fn cert(&self) -> Option<&Cert> {
        match &self.obj {
            PgpDigParamsObj::Cert(cert) => Some(cert),
            PgpDigParamsObj::Subkey(cert, _) => Some(cert),
            PgpDigParamsObj::Signature(_) => None,
        }
    }

    fn key(&self) -> Option<ErasedKeyAmalgamation<PublicParts>> {
        match &self.obj {
            PgpDigParamsObj::Cert(cert) => {
                Some(cert.primary_key().into())
            }
            PgpDigParamsObj::Subkey(cert, fpr) => {
                Some(cert.keys().subkeys()
                     .key_handle(fpr)
                     .next()
                     .expect("subkey missing")
                     .into())
            }
            PgpDigParamsObj::Signature(_) => None,
        }
    }

    fn signature(&self) -> Option<&Signature> {
        match &self.obj {
            PgpDigParamsObj::Cert(_) => None,
            PgpDigParamsObj::Subkey(_, _) => None,
            PgpDigParamsObj::Signature(sig) => Some(sig),
        }
    }
}

ffi!(
/// Returns the signature's type.
///
/// If `dig` is NULL or does not contain a signature, then this
/// function returns -1.
fn _pgpSignatureType(dig: *const PgpDigParams) -> c_int[-1] {
    let dig = check_ptr!(dig);

    dig.signature()
        .ok_or_else(|| Error::Fail("Not a signature".into()))
        .map(|sig| {
            u8::from(sig.typ()).into()
        })
});

ffi!(
/// Frees the parameters.
fn _pgpDigParamsFree(dig: Option<&mut PgpDigParams>) {
    free!(dig);
});

ffi!(
/// "Compares" the two parameters and returns 1 if they differ and 0 if
/// they match.
///
/// Two signatures are considered the same if they have the same
/// parameters (version, signature type, public key and hash
/// algorithms, and the first issuer packet).  Note: this function
/// explicitly does not check that the MPIs are the same, nor that the
/// signature creation time is the same!  This is intended.  The only
/// use of this function in the rpm code base is to check whether a key
/// has already made a signature (cf. sign/rpmgensig.c:haveSignature).
///
/// Two certificates are considered the same if they have the same
/// fingerprint.  (rpm does not currently use this functionality.)
///
/// Two subkeys are considered the same if they have the same
/// fingerprint.  (rpm does not currently use this functionality.)
fn _pgpDigParamsCmp(p1: *const PgpDigParams,
                    p2: *const PgpDigParams)
     -> c_int[1]
{
    let p1 = check_ptr!(p1);
    let p2 = check_ptr!(p2);

    let r = match (&p1.obj, &p2.obj) {
        (PgpDigParamsObj::Cert(c1), PgpDigParamsObj::Cert(c2)) => {
            c1.fingerprint() == c2.fingerprint()
        }
        (PgpDigParamsObj::Subkey(_, f1), PgpDigParamsObj::Subkey(_, f2)) => {
            f1 == f2
        }
        (PgpDigParamsObj::Signature(s1), PgpDigParamsObj::Signature(s2)) => {
            t!("s1: {:?}", s1);
            t!("s2: {:?}", s2);
            s1.hash_algo() == s2.hash_algo()
                && s1.pk_algo() == s2.pk_algo()
                && s1.version() == s2.version()
                && s1.typ() == s2.typ()
                && p1.signid == p2.signid
        }
        _ => {
            false
        }
    };

    Ok(if r { 0 } else { 1 })
});

const PGPVAL_PUBKEYALGO: c_uint = 6;
const PGPVAL_HASHALGO: c_uint = 9;

ffi!(
/// Returns the object's public key or algorithm algorithm.
///
/// `algotype` is either `PGPVAL_PUBKEYALGO` or `PGPVAL_HASHALGO`.
/// Other algo types are not support and cause this function to return
/// 0.
fn _pgpDigParamsAlgo(dig: *const PgpDigParams,
                     algotype: c_uint) -> c_uint[0]
{
    let dig = check_ptr!(dig);

    match (algotype, &dig.obj) {
        // pubkey algo.
        (PGPVAL_PUBKEYALGO, PgpDigParamsObj::Cert(cert)) => {
            Ok(u8::from(cert.primary_key().key().pk_algo()).into())
        }
        (PGPVAL_PUBKEYALGO, PgpDigParamsObj::Subkey(_, _)) => {
            Ok(u8::from(dig.key().expect("valid").key().pk_algo()).into())
        }
        (PGPVAL_PUBKEYALGO, PgpDigParamsObj::Signature(sig)) => {
            Ok(u8::from(sig.pk_algo()).into())
        }

        // hash algo.
        (PGPVAL_HASHALGO, PgpDigParamsObj::Cert(cert)) => {
            match cert.with_policy(&*P.read().unwrap(), None) {
                Ok(vc) => {
                    let algo = vc.primary_key().binding_signature().hash_algo();
                    Ok(u8::from(algo).into())
                }
                Err(err) => {
                    Err(Error::Fail(
                        format!("Using {}: {}", cert.fingerprint(), err)))
                }
            }
        }
        (PGPVAL_HASHALGO, PgpDigParamsObj::Subkey(_, fpr)) => {
            let ka = dig.key().expect("valid");
            match ka.with_policy(&*P.read().unwrap(), None) {
                Ok(ka) => {
                    let algo = ka.binding_signature().hash_algo();
                    Ok(u8::from(algo).into())
                }
                Err(err) => {
                    Err(Error::Fail(
                        format!("Using {}: {}", fpr, err)))
                }
            }
        }
        (PGPVAL_HASHALGO, PgpDigParamsObj::Signature(sig)) => {
            Ok(u8::from(sig.hash_algo()).into())
        }

        // Unknown algo.
        (t, PgpDigParamsObj::Cert(_))
        | (t, PgpDigParamsObj::Subkey(_, _))
        | (t, PgpDigParamsObj::Signature(_)) => {
            Err(Error::Fail(format!("Invalid algorithm type: {}", t)))
        }
    }
});

ffi!(
/// Returns the issuer or the Key ID.
///
/// If `dig` is a signature, then this returns the Key ID stored in the
/// first Issuer or Issuer Fingerprint subpacket as a hex string.
/// (This is not authenticated!)
///
/// If `dig` is a certificate or a subkey, then this returns the key's
/// Key ID.
///
/// The caller must *not* free the returned buffer.
fn _pgpDigParamsSignID(dig: *const PgpDigParams) -> *const u8 {
    let dig = check_ptr!(dig);
    t!("SignID: {}",
       dig.signid.iter().map(|v| format!("{:02X}", v)).collect::<String>());
    Ok(dig.signid.as_ptr())
});

ffi!(
/// Returns the primary User ID, if any.
///
/// If `dig` is a signature, then this returns `NULL`.
///
/// If `dig` is a certificate or a subkey, then this returns the
/// certificate's primary User ID, if any.
///
/// This interface does not provide a way for the caller to recognize
/// any embedded `NUL` characters.
///
/// The caller must *not* free the returned buffer.
fn _pgpDigParamsUserID(dig: *const PgpDigParams) -> *const c_char {
    let dig = check_ptr!(dig);
    if let Some(ref userid) = dig.userid {
        Ok(userid.as_ptr())
    } else {
        Ok(std::ptr::null())
    }
});

ffi!(
/// Returns the object's version.
///
/// If `dig` is a signature, then this returns the version of the
/// signature packet.
///
/// If `dig` is a certificate, then this returns the version of the
/// primary key packet.
///
/// If `dig` is a subkey, then this returns the version of the subkey's
/// key packet.
fn _pgpDigParamsVersion(dig: *const PgpDigParams) -> c_int[0] {
    let dig = check_ptr!(dig);
    let version = match &dig.obj {
        PgpDigParamsObj::Cert(cert) => {
            cert.primary_key().key().version()
        }
        PgpDigParamsObj::Subkey(_, _) => {
            dig.key().unwrap().key().version()
        }
        PgpDigParamsObj::Signature(sig) => {
            sig.version()
        }
    };
    Ok(version as c_int)
});

ffi!(
/// Returns the object's time.
///
/// If `dig` is a signature, then this returns the signature's creation
/// time.
///
/// If `dig` is a certificate, then this returns the primary key's key
/// creation time.
///
/// If `dig` is a subkey, then this returns the subkey's key creation
/// time.
fn _pgpDigParamsCreationTime(dig: *const PgpDigParams) -> u32[0] {
    let dig = check_ptr!(dig);
    let t = match &dig.obj {
        PgpDigParamsObj::Cert(cert) => {
            cert.primary_key().key().creation_time()
        }
        PgpDigParamsObj::Subkey(cert, fpr) => {
            cert.keys().subkeys()
                .key_handle(fpr)
                .next()
                .expect("subkey missing")
                .key()
                .creation_time()
        }
        PgpDigParamsObj::Signature(sig) => {
            sig.signature_creation_time().unwrap_or(UNIX_EPOCH)
        }
    };
    Ok(t.duration_since(UNIX_EPOCH)
       .map_err(|_| Error::Fail("time".into()))?
       .as_secs() as u32)
});

ffi!(
/// Verifies the signature.
///
/// If `key` is `NULL`, then this computes the hash and checks it
/// against the hash prefix.
///
/// If `key` is not `NULL`, then this checks that the signature is
/// correct.
///
/// This function does not modify `ctx`.  Instead, it first duplicates
/// `ctx` and then hashes the the meta-data into that context.
///
/// This function fails if the signature is not valid, or a supplied
/// key is not valid.
///
/// A signature is valid if:
///
///   - The signature is alive now (not created in the future, and not
///     yet expired)
///
///   - It is accepted by the [policy].
///
/// A key is valid if as of the *signature's* creation time if:
///
///   - The certificate is valid according to the [policy].
///
///   - The certificate is alive
///
///   - The certificate is not revoke
///
///   - The key is alive
///
///   - The key is not revoke
///
///   - The key has the signing capability set.
///
/// [policy]: index.html#policy
fn _pgpVerifySignature(key: *const PgpDigParams,
                       sig: *const PgpDigParams,
                       ctx: *const digest::DigestContext) -> ErrorCode {
    match _pgpVerifySignature2(key, sig, ctx, std::ptr::null_mut()) {
        0 => Ok(()),
        ec => Err(Error::from(ec)),
    }
});

ffi!(
/// Like _pgpVerifySignature, but returns error messages and lints in
/// `lint_str`.
fn _pgpVerifySignature2(key: *const PgpDigParams,
                        sig: *const PgpDigParams,
                        ctx: *const digest::DigestContext,
                        lint_str: *mut *mut c_char) -> ErrorCode {
    let key: Option<&PgpDigParams> = check_optional_ptr!(key);
    let sig: &PgpDigParams = check_ptr!(sig);
    // This function MUST NOT free or even change ctx.
    let mut ctx = check_ptr!(ctx).clone();
    let mut lint_str: Option<&mut _> = check_optional_mut!(lint_str);

    if let Some(lint_str) = lint_str.as_mut() {
        **lint_str = std::ptr::null_mut();
    }

    let mut lints = Vec::new();
    let r = pgp_verify_signature(key, sig, ctx, &mut lints);

    // Return any lint / error messages.
    if lints.len() > 0 {
        let mut s: String = if let Some(key) = key {
            format!(
                "Verifying a signature using certificate {} ({}):",
                key.cert()
                    .map(|cert| cert.fingerprint().to_string())
                    .unwrap_or_else(|| "<invalid certificate>".to_string()),
                key.cert()
                    .and_then(|cert| {
                        cert.userids().next()
                            .map(|userid| {
                                String::from_utf8_lossy(userid.userid().value()).into_owned()
                            })
                    })
                    .unwrap_or_else(|| {
                        "<unknown>".into()
                    }))
        } else {
            format!(
                "Verifying a signature, but no certificate was \
                 provided:")
        };

        // Indent the lints.
        let sep = "\n  ";

        let lints_count = lints.len();
        for (err_i, err) in lints.into_iter().enumerate() {
            for (cause_i, cause) in error_chain(&err).into_iter().enumerate() {
                if cause_i == 0 {
                    s.push_str(sep);
                    if lints_count > 1 {
                        s.push_str(&format!("{}. ", err_i + 1));
                    }
                } else {
                    s.push_str(sep);
                    s.push_str("    because: ");
                }
                s.push_str(&cause);
            }
        }

        t!("Lints: {}", s);

        if let Some(lint_str) = lint_str.as_mut() {
            // Add a trailing NUL.
            s.push('\0');

            **lint_str = s.as_mut_ptr() as *mut c_char;
            // Pass ownership to the caller.
            std::mem::forget(s);
        }
    }

    r
});

// Verifies the signature.
//
// Lints are appended to `lints`.  Note: multiple lints may be added.
fn pgp_verify_signature(key: Option<&PgpDigParams>,
                        sig: &PgpDigParams,
                        mut ctx: digest::DigestContext,
                        lints: &mut Vec<anyhow::Error>)
    -> Result<()>
{
    tracer!(*crate::TRACE, "pgp_verify_signature");

    linter!($, lints);

    // Whether the verification relies on legacy cryptography.
    let mut legacy = false;

    let sig = sig.signature().ok_or_else(|| {
        Error::Fail("sig parameter does not designate a signature".into())
    })?;

    let sig_id = || {
        let digest_prefix = sig.digest_prefix();
        format!("{:02x}{:02x} created at {}",
                digest_prefix[0],
                digest_prefix[1],
                if let Some(t) = sig.signature_creation_time() {
                    DateTime::<Utc>::from(t)
                        .format("%c").to_string()
                } else {
                    "<unknown>".to_string()
                })
    };

    let sig_time = if let Some(t) = sig.signature_creation_time() {
        t
    } else {
        return_err!(
            None,
            "Signature {} invalid: signature missing a creation time",
            sig_id());
    };

    // Allow some clock skew.
    if let Err(err) = sig.signature_alive(None,  Duration::new(5 * 60, 0)) {
        return_err!(
            Some(err),
            "Signature {} invalid: signature is not alive",
            sig_id());
    }

    {
        let policy = P.read().unwrap();
        if let Err(err) = policy.signature(sig, Default::default()) {
            if NP.signature(sig, Default::default()).is_ok() {
                legacy = true;
                add_lint!(
                    Some(err),
                    "Signature {} invalid: signature relies on legacy cryptography",
                    sig_id());
            } else {
                return_err!(
                    Some(err),
                    "Signature {} invalid: policy violation", sig_id());
            }
        }
        // XXX: As of sequoia-openpgp v1.11.0, this check is not done
        // by `policy.signature` (see issue #953).  We do it manually,
        // but once rpm-sequoia depends on a newer version of
        // sequoia-openpgp that does this, remove this code.
        if let Err(err) = policy.packet(&Packet::from(sig.clone())) {
            if NP.packet(&Packet::from(sig.clone())).is_ok() {
                legacy = true;
                add_lint!(
                    Some(err),
                    "Signature {} invalid: signature relies on legacy cryptography",
                    sig_id());
            } else {
                return_err!(
                    Some(err),
                    "Signature {} invalid: policy violation", sig_id());
            }
        }
    }

    // XXX: rpm only cares about the first issuer
    // subpacket.
    let issuer = match sig.get_issuers().into_iter().next() {
        Some(issuer) => issuer,
        None => return_err!(
            None,
            "Signature {} invalid: signature has no issuer subpacket",
            sig_id()),
    };

    if let Some(key) = key {
        // Actually verify the signature.
        let cert = key.cert().ok_or_else(|| {
            Error::Fail("key parameter is not a cert".into())
        })?;
        let subkey = key.key().expect("is a certificate").key().fingerprint();

        t!("Checking signature {} using {} with {} / {}",
           sig_id(), sig.hash_algo(),
           cert.fingerprint(), subkey);

        // We evaluate the certificate as of the signature creation
        // time.
        let p = &*P.read().unwrap();
        let vc = cert.with_policy(p, sig_time)
            .or_else(|err| {
                // Try again, but use the current time as a reference
                // time.  It is quite common for old self-signatures
                // to be stripped.
                match cert.with_policy(p, None) {
                    Ok(vc) => {
                        // We'd really like to emit the following
                        // lint, but for most users it is not
                        // actionable.  When the ecosystem changes so
                        // that certificates include older self
                        // signatures, enable it again.

                        // add_lint!(
                        //     None,
                        //     "Certificate has no valid binding signature \
                        //      as of the signature's creation time, but \
                        //      is valid now.  The certificate has probably \
                        //      been stripped or minimized.");
                        Ok(vc)
                    }
                    Err(err2) => {
                        add_lint!(
                            Some(err),
                            "Certificate {} invalid: policy violation",
                            cert.keyid());
                        Err(err2)
                    }
                }
            })
            .or_else(|err| {
                legacy = true;
                add_lint!(
                    Some(err),
                    "Certificate {} invalid: policy violation",
                    cert.keyid());
                cert.with_policy(NP, sig_time)
            })?;

        if let Err(err) = vc.alive() {
            legacy = true;
            add_lint!(
                Some(err),
                "Certificate {} invalid: certificate is not alive",
                vc.keyid());
        }
        if let RevocationStatus::Revoked(_) = vc.revocation_status() {
            legacy = true;
            add_lint!(
                None,
                "Certificate {} invalid: certificate is revoked",
                vc.keyid());
        }

        // Find the key.
        match vc.keys().key_handle(issuer.clone()).next() {
            Some(ka) => {
                if ka.key().fingerprint() != subkey {
                    return_err!(None,
                                "Key {} invalid: wrong subkey ({})",
                                ka.key().keyid(), subkey);
                }
                if ! ka.for_signing() {
                    return_err!(None,
                                "Key {} invalid: not signing capable",
                                ka.key().keyid());
                }
                if let Err(err) = ka.alive() {
                    legacy = true;
                    add_lint!(Some(err),
                              "Key {} invalid: key is not alive",
                              ka.key().keyid());
                }
                if let RevocationStatus::Revoked(_) = ka.revocation_status() {
                    legacy = true;
                    add_lint!(None,
                              "Key {} is invalid: key is revoked",
                              ka.key().keyid());
                }

                // Finally we can verify the signature.
                sig.clone().verify_hash(ka.key(), ctx.ctx.clone())?;
                if legacy {
                    return Err(Error::NotTrusted(
                        "Verification relies on legacy crypto".into())
                               .into());
                } else {
                    return Ok(());
                }
            }
            None => {
                return_err!(None,
                            "Certificate {} does not contain key {} \
                             or it is not valid",
                            vc.keyid(), issuer);
            }
        }
    } else {
        // We don't have a key, but we still check that the prefix is
        // correct.

        // These traits should be imported only where needed to avoid
        // bugs.
        use openpgp::serialize::Marshal;
        use openpgp::serialize::MarshalInto;

        // See https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.4
        let mut sig_data = Vec::with_capacity(128);

        // Hash the signature into the context.
        match sig.version() {
            4 => {
                sig_data.push(sig.version());
                sig_data.push(sig.typ().into());
                sig_data.push(sig.pk_algo().into());
                sig_data.push(sig.hash_algo().into());

                let l = sig.hashed_area().serialized_len() as u16;
                sig_data.push((l >> 8) as u8);
                sig_data.push((l >> 0) as u8);

                sig.hashed_area().serialize(&mut sig_data).expect("vec");

                let sig_len = sig_data.len();

                // Trailer.
                sig_data.push(sig.version());
                sig_data.push(0xFF);
                sig_data.push((sig_len >> 24) as u8);
                sig_data.push((sig_len >> 16) as u8);
                sig_data.push((sig_len >>  8) as u8);
                sig_data.push((sig_len >>  0) as u8);
            }
            3 => {
                sig_data.push(sig.typ().into());
                let ct = sig.signature_creation_time().unwrap_or(UNIX_EPOCH);
                let ct = ct.duration_since(UNIX_EPOCH)
                    .map_err(|_| Error::Fail("time".into()))?
                    .as_secs() as u32;
                sig_data.push((ct >> 24) as u8);
                sig_data.push((ct >> 16) as u8);
                sig_data.push((ct >>  8) as u8);
                sig_data.push((ct >>  0) as u8);
            }
            v => {
                return Err(Error::Fail(
                    format!("Unsupported signature version: {}", v)));
            }
        }

        ctx.update(&sig_data);

        let digest_size = ctx.digest_size();
        let mut digest: Vec<u8> = Vec::with_capacity(digest_size);
        for _ in 0..digest_size {
            digest.push(0);
        }
        ctx.digest(&mut digest[..])?;

        let p = sig.digest_prefix();
        if p[0] != digest[0] || p[1] != digest[1] {
            return Err(Error::Fail("digest prefix mismatch".into()));
        } else {
            t!("digest prefix matches");
        }

        return Err(Error::NoKey(
            format!("Not provided (issuer: {})", issuer).into()));
    }
}

ffi!(
/// Returns the Key ID of the public key or the secret key stored in
/// `pkt`.
///
/// Returns -1 if `pkt` is not a public key or secret key.
///
/// Note: this function does not handle public subkeys or secret
/// subkeys!
///
/// `keyid` must be allocated by the caller and points to at least 8
/// bytes of memory.
///
/// Returns 0 on success and -1 on failure.
fn _pgpPubkeyKeyID(pkt: *const u8, pktlen: size_t, keyid: *mut u8)
     -> Binary
{
    let pkt = check_slice!(pkt, pktlen);

    let ppr = PacketParser::from_bytes(pkt)?;
    let k = if let PacketParserResult::Some(ref pp) = ppr {
        match &pp.packet {
            Packet::PublicKey(key) => Some(key.keyid()),
            Packet::SecretKey(key) => Some(key.keyid()),
            _ => None,
        }
    } else {
        None
    };

    t!("Key ID: {}",
       k.as_ref()
           .map(|k| k.to_string())
           .unwrap_or_else(|| String::from("none")));

    if let Some(k) = k {
        let buffer = check_mut_slice!(keyid, 8);
        buffer.copy_from_slice(k.as_bytes());

        Ok(())
    } else {
        Err(Error::Fail("Not a key".into()))
    }
});

ffi!(
/// Calculate OpenPGP public key fingerprint.
///
/// Returns -1 if `pkt` is not a public key or secret key.
///
/// Note: this function does not handle public subkeys or secret
/// subkeys!
///
/// `*fprout` is allocated using `malloc` and must be allocated by the
/// caller.
///
/// Returns 0 on success and -1 on failure.
fn _pgpPubkeyFingerprint(pkt: *const u8, pktlen: size_t,
                         fprout: *mut *mut u8, fprlen: *mut size_t)
     -> Binary
{
    let pkt = check_slice!(pkt, pktlen);

    let ppr = PacketParserBuilder::from_bytes(pkt)?
        .dearmor(Dearmor::Disabled) // Disable dearmoring.
        .build()?;
    let fpr = if let PacketParserResult::Some(ref pp) = ppr {
        match &pp.packet {
            Packet::PublicKey(key) => Some(key.fingerprint()),
            Packet::SecretKey(key) => Some(key.fingerprint()),
            _ => None,
        }
    } else {
        None
    };

    t!("Fingerprint: {}",
       fpr.as_ref()
           .map(|fpr| fpr.to_string())
           .unwrap_or_else(|| String::from("none")));

    if let Some(fpr) = fpr {
        let fpr = fpr.as_bytes();
        unsafe {
            let buffer = libc::malloc(fpr.len());
            libc::memcpy(buffer, fpr.as_ptr() as *const c_void, fpr.len());
            *fprout = buffer as *mut u8;
            *fprlen = fpr.len();
        }

        Ok(())
    } else {
        Err(Error::Fail("Not a key".into()))
    }
});

ffi!(
/// Wraps the data in ASCII armor.
///
/// `atype` is the armor type.
///
/// The caller must free the returned buffer.
///
/// Returns `NULL` on failure.
fn _pgpArmorWrap(atype: c_int, s: *const c_char, ns: size_t)
     -> *mut c_char
{
    let atype = armor::Kind::try_from(PgpArmor::from(atype))?;
    let s = check_slice!(s, ns);

    let mut writer = armor::Writer::new(Vec::new(), atype)
        .map_err(|err| Error::Fail(format!("creating armor writer: {}", err)))?;
    writer.write(s)
        .map_err(|err| Error::Fail(format!("writing armor body: {}", err)))?;

    let mut buffer = writer.finalize()
        .map_err(|err| Error::Fail(format!("finalizing armor: {}", err)))?;
    // Add a trailing NUL.
    buffer.push(0);

    let ptr = buffer.as_mut_ptr() as *mut c_char;
    std::mem::forget(buffer);

    Ok(ptr)
});

ffi!(
/// Returns the length of the certificate in bytes.
///
/// `pkts` points to a buffer.  Fails if `pkts` does not point to
/// exactly one valid OpenPGP certificate.
///
/// Returns 0 on failure.
fn _pgpPubKeyCertLen(pkts: *const u8, pktslen: size_t,
                     certlen: *mut size_t) -> Binary
{
    use openpgp::packet::Header;
    use openpgp::packet::header::PacketLengthType;
    use openpgp::packet::header::BodyLength;
    use openpgp::packet::header::CTB;
    use buffered_reader::BufferedReader;

    let pkts = check_slice!(pkts, pktslen);
    let certlen = check_mut!(certlen);

    // XXX: These functions are more or less copied from
    // sequoia/openpgp/src/parse.rs.  When sequoia-openpgp makes them
    // public, we drop this copy.
    fn body_length_parse_new_format<T, C>(bio: &mut T)
        -> openpgp::Result<BodyLength>
        where T: BufferedReader<C>, C: Debug + Send + Sync
    {
        let octet1 : u8 = bio.data_consume_hard(1)?[0];
        match octet1 {
            0..=191 => // One octet.
                Ok(BodyLength::Full(octet1 as u32)),
            192..=223 => { // Two octets length.
                let octet2 = bio.data_consume_hard(1)?[0];
                Ok(BodyLength::Full(((octet1 as u32 - 192) << 8)
                                    + octet2 as u32 + 192))
            },
            224..=254 => // Partial body length.
                Ok(BodyLength::Partial(1 << (octet1 & 0x1F))),
            255 => // Five octets.
                Ok(BodyLength::Full(bio.read_be_u32()?)),
        }
    }

    /// Decodes an old format body length as described in [Section
    /// 4.2.1 of RFC 4880].
    ///
    ///   [Section 4.2.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2.1
    fn body_length_parse_old_format<T, C>(bio: &mut T,
                                          length_type: PacketLengthType)
         -> openpgp::Result<BodyLength>
        where T: BufferedReader<C>, C: Debug + Send + Sync
    {
        match length_type {
            PacketLengthType::OneOctet =>
                Ok(BodyLength::Full(bio.data_consume_hard(1)?[0] as u32)),
            PacketLengthType::TwoOctets =>
                Ok(BodyLength::Full(bio.read_be_u16()? as u32)),
            PacketLengthType::FourOctets =>
                Ok(BodyLength::Full(bio.read_be_u32()? as u32)),
            PacketLengthType::Indeterminate =>
                Ok(BodyLength::Indeterminate),
        }
    }

    fn parse_header<T, C>(bio: &mut T)
        -> openpgp::Result<Header>
        where T: BufferedReader<C>, C: Debug + Send + Sync
    {
        let ctb = CTB::try_from(bio.data_consume_hard(1)?[0])?;
        let length = match ctb {
            CTB::New(_) => body_length_parse_new_format(bio)?,
            CTB::Old(ref ctb) =>
                body_length_parse_old_format(bio, ctb.length_type())?,
        };
        return Ok(Header::new(ctb, length));
    }

    let mut br = buffered_reader::Memory::new(pkts);

    let mut found_cert = false;
    let len: Option<usize> = loop {
        // The start of this packet as a byte offset into buffer.
        let start_of_packet = br.total_out();

        if start_of_packet == pkts.len() {
            // We're done.
            break Some(start_of_packet);
        }

        let header = match parse_header(&mut br) {
            Ok(header) => header,
            Err(err) => {
                t!("Error reading certificate at offset {}: {}",
                   start_of_packet, err);
                break None;
            }
        };

        use Tag::*;
        let t = header.ctb().tag();
        t!("Found a {:?} at offset {}, length: {:?}",
           t, start_of_packet, header.length());
        match t {
            // Start of a new certificate.
            PublicKey | SecretKey => {
                if found_cert {
                    break Some(start_of_packet);
                } else {
                    found_cert = true;
                }
            }

            // The body of a certificate.
            PublicSubkey
            | SecretSubkey
            | UserID
            | UserAttribute
            | Signature
            | Marker
            | Trust
            | Unknown(_)
            | Private(_) => {
                if start_of_packet == 0 {
                    t!("Encountered a ({:?}) at offset {}, \
                        which is not a valid start of a certificate",
                       t, start_of_packet);
                    break None;
                }
            }

            Reserved
            | PKESK
            | SKESK
            | OnePassSig
            | CompressedData
            | SED
            | Literal
            | SEIP
            | MDC
            | AED =>
            {
                t!("Encountered a ({:?}) at offset {}, \
                    which does not belong in a certificate",
                   t, start_of_packet);
                break None;
            }

            t => if t.is_critical() {
                t!("Encountered a ({:?}) at offset {}, \
                    which does not belong in a certificate",
                   t, start_of_packet);
                break None;
            } else {
                // Ignore unknown non-critical packet.
            },
        }

        // Advance to the next packet.
        match header.length() {
            BodyLength::Full(l) => {
                let l = *l as usize;
                if let Err(err) = br.data_consume_hard(l) {
                    t!("Error while reading packet: {}", err);
                    break None;
                }
            }
            BodyLength::Partial(_) => {
                t!("Packet {} has partial body length, \
                    which is unsupported by keyring splitter",
                   t);
                break None;
            }
            BodyLength::Indeterminate => {
                t!("Packet {} has intedeterminite length, \
                    which is unsupported by keyring splitter",
                   t);
                break None;
            }
        }
    };

    if let Some(len) = len {
        *certlen = len;
        Ok(())
    } else {
        Err(Error::Fail("No certificate found".into()))
    }
});

ffi!(
/// Parses OpenPGP data.
///
/// If `pkts` contains a signature and `pkttype` is 0 or
/// `Tag::Signature`, this returns a `PgpDigParams` containing a
/// signature.
///
/// If `pkts` contains a certificate and `pkttype` is 0,
/// `Tag::PublicKey`, or `Tag::SecretKey`, this returns a
/// `PgpDigParams` containing a certificate.  The certificate is
/// checked for validity in the sense that it only contains packets
/// that belong to a certificate; this function does **not** check the
/// binding signatures, etc.  That check is done when the key is used
/// in [_pgpVerifySignature].
///
/// Returns 0 on success, -1 on failure.
fn _pgpPrtParams(pkts: *const u8, pktlen: size_t,
                 pkttype: c_uint, paramsp: *mut *mut PgpDigParams)
    -> Binary
{
    match _pgpPrtParams2(pkts, pktlen, pkttype, paramsp, std::ptr::null_mut()) {
        0 => Ok(()),
        ec => Err(Error::from(ec)),
    }
});

ffi!(
/// Like _pgpPrtParams, but returns error messages and lints in
/// `lint_str`.
fn _pgpPrtParams2(pkts: *const u8, pktlen: size_t,
                  pkttype: c_uint, paramsp: *mut *mut PgpDigParams,
                  lint_str: *mut *mut c_char)
    -> Binary
{
    let mut lint_str: Option<&mut _> = check_optional_mut!(lint_str);

    if let Some(lint_str) = lint_str.as_mut() {
        **lint_str = std::ptr::null_mut();
    }

    let mut lints = Vec::new();
    let r = pgp_prt_params(pkts, pktlen, pkttype, paramsp, &mut lints);

    // Return any lint / error messages.
    if lints.len() > 0 {
        let mut s: String = format!("Parsing an OpenPGP packet:");

        // Indent the lints.
        let sep = "\n  ";

        let lints_count = lints.len();
        for (err_i, err) in lints.into_iter().enumerate() {
            for (cause_i, cause) in error_chain(&err).into_iter().enumerate() {
                if cause_i == 0 {
                    s.push_str(sep);
                    if lints_count > 1 {
                        s.push_str(&format!("{}. ", err_i + 1));
                    }
                } else {
                    s.push_str(sep);
                    s.push_str("    because: ");
                }
                s.push_str(&cause);
            }
        }

        t!("Lints: {}", s);

        if let Some(lint_str) = lint_str.as_mut() {
            // Add a trailing NUL.
            s.push('\0');

            **lint_str = s.as_mut_ptr() as *mut c_char;
            // Pass ownership to the caller.
            std::mem::forget(s);
        }
    }

    r
});

fn pgp_prt_params(pkts: *const u8, pktlen: size_t,
                  pkttype: c_uint, paramsp: *mut *mut PgpDigParams,
                  lints: &mut Vec<anyhow::Error>)
    -> Result<()>
{
    tracer!(*crate::TRACE, "pgp_prt_params");

    linter!($, lints);

    let pkttype: Option<Tag> = if pkttype == 0 {
        None
    } else {
        Some(Tag::from(pkttype as u8))
    };

    let pkts = check_slice!(pkts, pktlen);
    let paramsp = check_mut!(paramsp);
    *paramsp = std::ptr::null_mut();

    let ppr = PacketParser::from_bytes(pkts)?;

    let (obj, issuer, userid) = if let PacketParserResult::Some(pp) = ppr {
        // Process the packet.
        match pp.packet {
            Packet::Signature(_)
                if pkttype.is_none() || pkttype == Some(Tag::Signature) =>
            {
                let (packet, next_ppr) = pp.next()?;

                if let PacketParserResult::Some(p) = next_ppr {
                    return_err!(None,
                                "Expected a bare OpenPGP signature, \
                                 but it's followed by a {}",
                                p.packet.tag());
                }

                let sig = if let Packet::Signature(sig) = packet {
                    sig
                } else {
                    panic!("it's a sig");
                };

                (PgpDigParamsObj::Signature(sig.clone()),
                 // XXX: Although there is normally only one issuer
                 // subpacket, there may be multiple such subpackets.
                 // Unfortunately, the API only allows us to return
                 // one.
                 sig.get_issuers().into_iter().next()
                     .map(|i| i.as_bytes().to_vec()),
                 None)
            }
            Packet::PublicKey(_) | Packet::SecretKey(_)
                if pkttype.is_none()
                    || pkttype == Some(Tag::PublicKey)
                    || pkttype == Some(Tag::SecretKey) =>
            {
                let cert = match CertParser::from(PacketParserResult::Some(pp)).next()
                {
                    Some(Ok(cert)) => cert,
                    Some(Err(err)) => return_err!(
                        Some(err),
                        "Failed to read an OpenPGP certificate"),
                    None => return_err!(
                        None,
                        "Failed to read an OpenPGP certificate"),
                };

                let keyid = cert.keyid().as_bytes().to_vec();

                let userid = if let Ok(vc)
                    = cert.with_policy(&*P.read().unwrap(), None)
                {
                    vc.primary_userid()
                        .ok()
                        .and_then(|u| {
                            CString::new(u.userid().value()).ok()
                        })
                } else {
                    None
                };

                (PgpDigParamsObj::Cert(cert),
                 Some(keyid),
                 userid)
            }
            Packet::Unknown(mut u) => {
                let mut err = u.set_error(anyhow::anyhow!("Error"));
                if let Some(openpgp::Error::MalformedMPI(_))
                    = err.downcast_ref::<openpgp::Error>()
                {
                    err = err.context("\
                        Signature appears to be created by a \
                        non-conformant OpenPGP implementation, see \
                        <https://github.com/rpm-software-management/rpm/issues/2351>.");
                }

                return_err!(Some(err), "Failed to parse {}", u.tag());
            }
            ref p => {
                return_err!(
                    None,
                    "Unexpected OpenPGP packet in this context {}",
                    p.tag());
            }
        }
    } else {
        return_err!(
            None,
            "Expected an OpenPGP packet, encountered the end of the file");
    };

    let mut buffer: [u8; 8] = [0; 8];
    if let Some(issuer) = issuer {
        let issuer = if issuer.len() > buffer.len() {
            // We've got a fingerprint.  For v4 keys, the last 16
            // bytes is the key id.
            &issuer[issuer.len() - buffer.len()..]
        } else {
            &issuer[..]
        };

        for (i, c) in issuer.into_iter().enumerate() {
            buffer[i] = *c as u8;
        }
    }

    *paramsp = move_to_c!(PgpDigParams {
        obj,
        signid: buffer,
        userid: userid,
    });

    Ok(())
}

ffi!(
/// Returns a `PgpDigParams` data structure for each subkey.
///
/// This does not return a `PgpDigParams` for the primary (just use
/// this one).  The subkeys are **not** checked for validity.  That
/// check is done when the key is used in [_pgpVerifySignature].
fn _pgpPrtParamsSubkeys(pkts: *const u8, pktlen: size_t,
                        _mainkey: *const PgpDigParams,
                        subkeys: *mut *mut PgpDigParams,
                        subkeys_count: *mut c_int) -> Binary {
    let pkts = check_slice!(pkts, pktlen);
    let subkeys = check_mut!(subkeys);
    *subkeys = std::ptr::null_mut();
    let subkeys_count = check_mut!(subkeys_count);

    let ppr = PacketParser::from_bytes(pkts)?;

    let cert = match ppr {
        PacketParserResult::Some(ref pp) => {
            match pp.packet {
                Packet::PublicKey(_) | Packet::SecretKey(_) => {
                    let cert = CertParser::from(ppr)
                        .next()
                        .ok_or(Error::Fail("Not an OpenPGP certificate".into()))??;
                    cert
                }
                ref p => {
                    return Err(Error::Fail(format!("{}", p.tag())));
                }
            }
        }
        _ => return Err(Error::Fail("Not an OpenPGP message".into())),
    };

    let userid = if let Ok(vc) = cert.with_policy(&*P.read().unwrap(), None) {
        vc.primary_userid()
            .ok()
            .and_then(|u| {
                CString::new(u.userid().value()).ok()
            })
    } else {
        None
    };

    // We return all subkeys here.  Subkeys are checked for validity
    // on demand.
    let mut keys: Vec<*mut PgpDigParams> = cert
        .keys().subkeys()
        .map(|ka| {
            t!("Subkey: {}", ka.key().keyid());

            let zeros = [0; 8];
            let mut dig = PgpDigParams {
                obj: PgpDigParamsObj::Subkey(cert.clone(), ka.key().fingerprint()),
                signid: zeros,
                userid: userid.clone(),
            };
            dig.signid.copy_from_slice(ka.key().keyid().as_bytes());
            move_to_c!(dig)
        })
        .collect();

    t!("Got {} subkeys", keys.len());
    *subkeys_count = keys.len() as c_int;
    if keys.len() == 0 {
        *subkeys = std::ptr::null_mut();
    } else {
        *subkeys = keys.as_mut_ptr() as *mut PgpDigParams;
        // Pass ownership to the caller.
        std::mem::forget(keys);
    }

    Ok(())
});

ffi!(
/// Strips the ASCII armor and returns the decoded data in `pkt`.
///
/// Despite its name, this function does not actually parse any OpenPGP
/// packets; it just strips the ASCII armor encoding.
///
/// Returns the type of armor on success (>0) or an error code
/// indicating the type of failure (<0).
fn _pgpParsePkts(armor: *const c_char,
                 pkt: *mut *mut c_char, pktlen: *mut size_t)
     -> PgpArmor
{
    let armor = check_cstr!(armor);
    let pkt = check_mut!(pkt);
    *pkt = std::ptr::null_mut();
    let pktlen = check_mut!(pktlen);

    let mut reader = armor::Reader::from_reader(
        std::io::BufReader::new(
            armor.to_str().map_err(|_| PgpArmorError::BodyDecode)?.as_bytes()),
        armor::ReaderMode::Tolerant(None));

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).map_err(|_| PgpArmorError::BodyDecode)?;

    let kind = reader.kind();

    *pktlen = buf.len() as size_t;
    *pkt = buf.as_mut_ptr() as *mut c_char;
    // Pass ownership to the caller.
    std::mem::forget(buf);

    Ok(kind.into())
});

ffi!(
/// Lints the first certificate in pkts.
///
/// This function links the certificate according to the current
/// [policy].  It warns about things like unusable subkeys, because they
/// do not have a valid binding signature.  It will also generate a
/// warning if there are no valid, signing-capable keys.
///
/// There are four cases:
///
/// - The packets do not describe a certificate: returns an error and
///   sets `*explanation` to `NULL`.
///
/// - The packets describe a certificate and the certificate is
///   completely unusable: returns an error and sets `*explanation` to
///   a human readable explanation.
///
/// - The packets describe a certificate and some components are not
///   usable: returns success, and sets `*explanation` to a human
///   readable explanation.
///
/// - The packets describe a certificate and there are no lints:
///   returns success, and sets `*explanation` to `NULL`.
///
/// [policy]: index.html#policy
fn _pgpPubKeyLint(pkts: *const c_char,
                  pktslen: size_t,
                  explanation: *mut *mut c_char) -> ErrorCode
{
    let pkts = check_slice!(pkts, pktslen);
    let explanation = check_mut!(explanation);

    // Make sure we always set explanation to something.
    *explanation = std::ptr::null_mut();

    let cert = CertParser::from_bytes(pkts)?.next()
        .ok_or(Error::Fail("Not an OpenPGP certificate".into()))??;

    let mut lints: Vec<String> = Vec::new();
    let mut lint = |l: &str| {
        lints.push(l.into());
    };

    let usable = 'done : loop {
        match cert.with_policy(&*P.read().unwrap(), None) {
            Err(err) => {
                lint(&format!("Policy rejects {}: {}", cert.keyid(), err));
                break 'done false;
            }
            Ok(vc) => {
                if let RevocationStatus::Revoked(revs)
                    = vc.revocation_status()
                {
                    for rev in revs {
                        if let Some((reason, msg))
                            = rev.reason_for_revocation()
                        {
                            let mut l = format!(
                                "The certificate was revoked: {}", reason);
                            if ! msg.is_empty() {
                                l.push_str(&format!(
                                    ", {}",
                                    String::from_utf8_lossy(msg)));
                            }
                            lint(&l);
                        } else {
                            lint("The certificate was revoked: \
                                  unspecified reason");
                        }
                    }
                }

                if let Err(err) = vc.alive() {
                    if let Some(e) = vc.primary_key().key_expiration_time() {
                        if e <= SystemTime::now() {
                            lint(&format!("The certificate is expired: {}",
                                          err));
                        } else {
                            lint(&format!("The certificate is not live: {}",
                                          err));
                        }
                    }
                }
            }
        };

        let mut have_signing = false;
        for ka in cert.keys() {
            let keyid = ka.key().keyid();

            match ka.with_policy(&*P.read().unwrap(), None) {
                Err(err) => {
                    lint(&format!("Policy rejects subkey {}: {}",
                                  keyid, err));
                    continue;
                }
                Ok(ka) => {
                    if ! ka.for_signing() {
                        // Silently ignore non-signing capable
                        // subkeys.  We don't care about them.
                        continue;
                    }

                    if let RevocationStatus::Revoked(revs)
                        = ka.revocation_status()
                    {
                        for rev in revs {
                            if let Some((reason, msg))
                                = rev.reason_for_revocation()
                            {
                                let mut l = format!(
                                    "Subkey {} was revoked: {}",
                                    keyid, reason);
                                if ! msg.is_empty() {
                                    l.push_str(&format!(
                                        ", {}",
                                        String::from_utf8_lossy(msg)));
                                }
                                lint(&l);
                            } else {
                                lint(&format!(
                                    "Subkey {} was revoked: \
                                     unspecified reason",
                                    keyid));
                            }
                        }
                        continue;
                    }

                    if let Err(err) = ka.alive() {
                        if let Some(e) = ka.key_expiration_time() {
                            if e <= SystemTime::now() {
                                lint(&format!("Subkey {} is expired: {}",
                                              keyid, err));
                            } else {
                                lint(&format!("Subkey {} is not live: {}",
                                              keyid, err));
                            }
                        }
                        continue;
                    }

                    if ! ka.key().pk_algo().is_supported() {
                        lint(&format!("Subkey {} is not supported \
                                       (no support for {})",
                                      keyid,
                                      ka.key().pk_algo()));
                        continue;
                    }

                    have_signing = true;
                }
            }
        }

        if ! have_signing {
            lint("Certificate does not have any usable signing keys");
        }

        break true;
    };

    if ! lints.is_empty() {
        // Indent the lints.
        let sep = "\n  ";

        let mut s: String = format!("Certificate {}:{}", cert.keyid(), sep);
        s.push_str(&lints.join(sep));
        s.push('\0');

        *explanation = s.as_mut_ptr() as *mut c_char;
        // Pass ownership to the caller.
        std::mem::forget(s);
    }

    if usable {
        Ok(())
    } else {
        Err(Error::Fail(format!("Certificate {} is unusable", cert.keyid())))
    }
});

/// An optional OpenPGP certificate *and* an optional signature.
///
/// This data structure is deprecated and is scheduled for removal in
/// rpm 4.19.
pub struct PgpDig {
    cert: Option<Box<PgpDigParams>>,
    sig: Option<Box<PgpDigParams>>,
}

/// Dump the packets to stderr.
///
/// This is used by _pgpPrtPkts, which is deprecated and is scheduled
/// for removal in rpm 4.19.  It is intended to be bug compatible with
/// rpm's internal implementation.
fn dump_packets(pkts: &[u8]) -> Result<()> {
    use openpgp::types::CompressionAlgorithm;
    use openpgp::types::KeyServerPreferences;
    use openpgp::types::PublicKeyAlgorithm;
    use openpgp::types::SignatureType;
    use openpgp::types::SymmetricAlgorithm;
    use openpgp::packet::signature::subpacket::Subpacket;
    use openpgp::packet::signature::subpacket::SubpacketTag;
    use openpgp::packet::signature::subpacket::SubpacketValue;

    let mut ppr = PacketParser::from_bytes(pkts)?;

    fn pk_algo(a: PublicKeyAlgorithm) -> &'static str {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match a {
            RSAEncryptSign => "RSA",
            RSAEncrypt => "RSA(Encrypt-Only)",
            RSASign => "RSA(Sign-Only)",
            ElGamalEncrypt => "Elgamal(Encrypt-Only)",
            DSA => "DSA",
            ECDH => "Elliptic Curve",
            ECDSA => "ECDSA",
            ElGamalEncryptSign => "Elgamal",
            EdDSA => "EdDSA",
            _ => "Unknown public key algorithm",
        }
    }

    fn sigtype(t: SignatureType) -> &'static str {
        use SignatureType::*;
        match t {
            Binary => "Binary document signature",
            Text => "Text document signature",
            Standalone => "Standalone signature",
            GenericCertification => "Generic certification of a User ID and Public Key",
            PersonaCertification => "Persona certification of a User ID and Public Key",
            CasualCertification => "Casual certification of a User ID and Public Key",
            PositiveCertification => "Positive certification of a User ID and Public Key",
            SubkeyBinding => "Subkey Binding Signature",
            PrimaryKeyBinding => "Primary Key Binding Signature",
            DirectKey => "Signature directly on a key",
            KeyRevocation => "Key revocation signature",
            SubkeyRevocation => "Subkey revocation signature",
            CertificationRevocation => "Certification revocation signature",
            Timestamp => "Timestamp signature",
            _ => "Unknown signature type",
        }
    }

    fn symalgo(a: SymmetricAlgorithm) -> &'static str {
        use SymmetricAlgorithm::*;
        #[allow(deprecated)]
        match a {
            Unencrypted => "Plaintext",
            IDEA => "IDEA",
            TripleDES => "3DES",
            CAST5 => "CAST5",
            Blowfish => "BLOWFISH",
            AES128 => "AES(128-bit key)",
            AES192 => "AES(192-bit key)",
            AES256 => "AES(256-bit key)",
            Twofish => "TWOFISH(256-bit key)",
            _ => "Unknown symmetric key algorithm",
        }
    }

    fn compalgo(a: CompressionAlgorithm) -> &'static str {
        use CompressionAlgorithm::*;
        match a {
            Uncompressed => "Uncompressed",
            Zip => "ZIP",
            Zlib => "ZLIB",
            BZip2 => "BZIP2",
            _ => "Unknown compression algorithm",
        }
    }

    fn ksprefs(prefs: KeyServerPreferences) -> &'static str {
        // This is wrong, but this is what the internal implementation
        // does.
        if prefs.no_modify() {
            "No-modify(128)"
        } else if KeyServerPreferences::empty().normalized_eq(&prefs) {
            ""
        } else {
            "Unknown key server preference"
        }
    }

    fn subpacket(sp: &Subpacket) -> String {
        let mut output: Vec<String> = Vec::new();

        let tag = sp.tag();
        let s = {
            use SubpacketTag::*;
            match tag {
                SignatureCreationTime => "signature creation time",
                SignatureExpirationTime => "signature expiration time",
                ExportableCertification => "exportable certification",
                TrustSignature => "trust signature",
                RegularExpression => "regular expression",
                Revocable => "revocable",
                KeyExpirationTime => "key expiration time",
                PlaceholderForBackwardCompatibility => "additional recipient request",
                PreferredSymmetricAlgorithms => "preferred symmetric algorithms",
                RevocationKey => "revocation key",
                Issuer => "issuer key ID",
                NotationData => "notation data",
                PreferredHashAlgorithms => "preferred hash algorithms",
                PreferredCompressionAlgorithms => "preferred compression algorithms",
                KeyServerPreferences => "key server preferences",
                PreferredKeyServer => "preferred key server",
                PrimaryUserID => "primary user id",
                PolicyURI => "policy URL",
                KeyFlags => "key flags",
                SignersUserID => "signer's user id",
                ReasonForRevocation => "reason for revocation",
                Features => "features",
                EmbeddedSignature => "embedded signature",
                _ => "Unknown signature subkey type",
            }
        };
        output.push(s.into());

        output.push(format!("({})", Into::<u8>::into(tag)));

        if sp.critical() {
            output.push(" *CRITICAL*".into());
        }

        {
            use SubpacketValue::*;
            match sp.value() {
                PreferredSymmetricAlgorithms(algos) => {
                    output.push(" ".into());
                    output.push(
                        algos.iter()
                            .map(|a| {
                                format!("{}({})",
                                        symalgo(*a),
                                        Into::<u8>::into(*a))
                            })
                            .collect::<Vec<String>>()
                            .join(" "))
                }
                PreferredHashAlgorithms(algos) => {
                    output.push(" ".into());
                    output.push(
                        algos.iter()
                            .map(|a| {
                                format!("{}({})",
                                        a.to_string(),
                                        Into::<u8>::into(*a))
                            })
                            .collect::<Vec<String>>()
                            .join(" "))
                }
                PreferredCompressionAlgorithms(algos) => {
                    output.push(" ".into());
                    output.push(
                        algos.iter()
                            .map(|a| {
                                format!("{}({})",
                                        compalgo(*a),
                                        Into::<u8>::into(*a))
                            })
                            .collect::<Vec<String>>()
                            .join(" "))
                }
                KeyServerPreferences(prefs) => {
                    output.push(format!(" {}", ksprefs(prefs.clone())))
                }
                SignatureExpirationTime(d)
                    | KeyExpirationTime(d) =>
                {
                    // expiration time is an offset from the creation
                    // time, but rpm's internal OpenPGP implementation
                    // treats it as an absolute time.  As we're going
                    // for bug-for-bug compatibility here, we do the
                    // same.
                    let t = DateTime::from_timestamp(
                        d.as_secs() as i64, 0)
                        // This is just compatibility, debugging
                        // output.  Fallback to the unix epoch.
                        .unwrap_or_default();
                    output.push(format!("  {}(0x{:08x})",
                                        t.format("%c"),
                                        d.as_secs()));
                }

                SignatureCreationTime(_)
                    | Issuer(_)
                    | KeyFlags(_) => (),

                _ => {
                    use sequoia_openpgp::serialize::MarshalInto;

                    output.push(" ".into());
                    output.extend(
                        sp.value()
                            .to_vec()
                            .unwrap_or(Vec::new())
                            .into_iter()
                            .map(|b| format!("{:02x}", b)))
                }
            }
        }

        output.join("")
    }

    while let PacketParserResult::Some(pp) = ppr {
        let (packet, next_ppr) = pp.recurse()?;
        ppr = next_ppr;

        // We only dump what rpm's internal OpenPGP implementation
        // dumps.  Other packets we silently ignore.
        #[allow(deprecated)]
        match packet {
            Packet::Signature(sig) => {
                // V4 Signature(2) DSA(17) SHA512(10) Generic certification of a User ID and Public Key(16)
                //     signature creation time(2)
                //     issuer key ID(16)
                //  signhash16 1418
                eprintln!("V{} Signature(2) {}({}) {}({}) {}({})",
                          sig.version(),
                          pk_algo(sig.pk_algo()),
                          Into::<u8>::into(sig.pk_algo()),
                          sig.hash_algo().to_string(),
                          Into::<u8>::into(sig.hash_algo()),
                          sigtype(sig.typ()),
                          Into::<u8>::into(sig.typ()));
                sig.hashed_area().iter().for_each(|sb| {
                    eprintln!("    {}", subpacket(sb));
                });
                sig.unhashed_area().iter().for_each(|sb| {
                    eprintln!("    {}", subpacket(sb));
                });

                eprintln!(" signhash16 {:02x}{:02x}",
                          sig.digest_prefix()[0],
                          sig.digest_prefix()[1]);
            },
            Packet::PublicKey(key) => {
                // V4 Public Key(6) RSA(1)  Tue Apr  7 08:52:57 2015(0x55239ae9)

                let secs = key.creation_time()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let t: DateTime::<Utc> = key.creation_time().into();

                eprintln!("V{} Public Key(6) {}({})  {}(0x{:08x})",
                          key.version(),
                          pk_algo(key.pk_algo()),
                          Into::<u8>::into(key.pk_algo()),
                          t.format("%c"), secs);
            }
            Packet::PublicSubkey(key) => {
                // Public Subkey(14) 045523a696010...
                use sequoia_openpgp::serialize::MarshalInto;

                let secs = key.creation_time()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                eprintln!("Public Subkey(14) {:02}{:08x}{:02x}{}",
                          key.version(), secs,
                          Into::<u8>::into(key.pk_algo()),
                          key.mpis().to_vec()
                          .unwrap_or_else(|_| Vec::new())
                          .into_iter()
                          .map(|b| format!("{:02x}", b))
                          .collect::<String>());
            }
            Packet::UserID(userid) => {
                // User ID(13) "Neal H. Walfield <neal@walfield.org>"
                eprintln!("User ID(13) {:?}",
                          String::from_utf8_lossy(userid.value()));
            }

            Packet::Unknown(_pkt) => (),
            Packet::OnePassSig(_ops) => (),
            Packet::SecretKey(_key) => (),
            Packet::SecretSubkey(_key) => (),
            Packet::Marker(_marker) => (),
            Packet::Trust(_trust) => (),
            Packet::UserAttribute(_ua) => (),
            Packet::Literal(_lit) => (),
            Packet::CompressedData(_cd) => (),
            Packet::PKESK(_pkesk) => (),
            Packet::SKESK(_skesk) => (),
            Packet::SEIP(_seip) => (),
            Packet::MDC(_mdc) => (),
            _ => (),
        }
    }

    Ok(())
}

ffi!(
/// Parses and optionally prints to stdout a OpenPGP packet(s).
///
/// This function is deprecated and is scheduled for removal in rpm
/// 4.19.
///
/// @param pkts		OpenPGP packet(s)
/// @param pktlen	OpenPGP packet(s) length (no. of bytes)
/// @param(out) dig	parsed output of signature/pubkey packet parameters
/// @param printing	should packets be printed?
///
/// Returns 0 on success, -1 on failure.
fn _pgpPrtPkts(pkts: *const u8, pktslen: size_t,
               dig: *mut PgpDig, printing: c_int)
    -> Binary
{
    let dig = check_mut!(dig);

    let mut params: *mut PgpDigParams = std::ptr::null_mut();

    if printing != 0 {
        // We ignore any error here as this printing should not change
        // the functions semantics.
        let _ = dump_packets(check_slice!(pkts, pktslen));
    }

    let result = _pgpPrtParams(pkts, pktslen, 0, &mut params);
    if result == -1 {
        return Err(Error::Fail("Parse error".into()));
    }

    let params = claim_from_c!(params);
    match params.obj {
        PgpDigParamsObj::Cert(_) => dig.cert = Some(params),
        PgpDigParamsObj::Subkey(_, _) => dig.cert = Some(params),
        PgpDigParamsObj::Signature(_) => dig.sig = Some(params),
    }

    Ok(())
});

ffi!(
/// Create a container for parsed OpenPGP packet(s).
///
/// This function is deprecated and is scheduled for removal in rpm
/// 4.19.
///
/// @return		container
fn _pgpNewDig() -> *mut PgpDig {
    Ok(move_to_c!(PgpDig {
        cert: None,
        sig: None,
    }))
});

ffi!(
/// Release (malloc'd) data from container.
///
/// This function is deprecated and is scheduled for removal in rpm
/// 4.19.
///
/// @param dig		container
fn _pgpCleanDig(dig: *mut PgpDig) {
    let dig = check_mut!(dig);
    dig.cert = None;
    dig.sig = None;
});

ffi!(
/// Destroy a container for parsed OpenPGP packet(s).
///
/// This function is deprecated and is scheduled for removal in rpm
/// 4.19.
///
/// @param dig		container
/// @return		NULL always
fn _pgpFreeDig(dig: Option<&mut PgpDig>) -> *mut PgpDig {
    free!(dig);
    Ok(std::ptr::null_mut())
});

ffi!(
/// Retrieve parameters for parsed OpenPGP packet(s).
///
/// This function is deprecated and is scheduled for removal in rpm
/// 4.19.
///
/// @param dig		container
/// @param pkttype	type of params to retrieve (signature / pubkey)
/// @return		pointer to OpenPGP parameters, NULL on error/not found
fn _pgpDigGetParams(dig: *const PgpDig, pkttype: c_uint)
    -> *const PgpDigParams
{
    let dig = check_ptr!(dig);

    let ptr = match Tag::from(pkttype as u8) {
        Tag::PublicKey => {
            if let Some(ref cert) = dig.cert {
                cert.as_ref()
            } else {
                std::ptr::null()
            }
        }
        Tag::Signature => {
            if let Some(ref sig) = dig.sig {
                sig.as_ref()
            } else {
                std::ptr::null()
            }
        }
        _ => {
            std::ptr::null()
        }
    };

    Ok(ptr)
});

ffi!(
/// Verify a PGP signature.
///
/// This function is deprecated and is scheduled for removal in rpm
/// 4.19.
///
/// @param dig		container
/// @param hashctx	digest context
/// @return 		RPMRC_OK on success
fn _pgpVerifySig(dig: *const PgpDig,
                 ctx: *const digest::DigestContext) -> ErrorCode {
    Err(
        _pgpVerifySignature(
            _pgpDigGetParams(dig, u8::from(Tag::PublicKey) as u32),
	    _pgpDigGetParams(dig, u8::from(Tag::Signature) as u32),
            ctx).into())
});

ffi!(
/// Merge the PGP packets of two certificates
///
/// The certificates must describe the same public key. The call should merge
/// important pgp packets (self-signatures, new subkeys, ...) and remove duplicates.
///
/// - `pkts1` - OpenPGP pointer to a buffer with the first certificate
/// - `pkts1len` - length of the buffer with the first certificate
/// - `pkts2` - OpenPGP pointer to a buffer with the second certificate
/// - `pkts2len` - length of the buffer with the second certificate
/// - `pktsm` - merged certificate (malloced)
/// - `pktsmlen` - length of merged certificate
/// - `flags` - merge flags (currently not used, must be zero)
///
/// Returns `RPMRC_OK` on success.
fn _pgpPubkeyMerge(
    pkts1: *const u8, pkts1len: size_t,
    pkts2: *const u8, pkts2len: size_t,
    pktsm: *mut *mut u8, pktsmlen: *mut size_t,
    flags: c_int)
  -> ErrorCode
{
    let pkts1 = check_slice!(pkts1, pkts1len);
    let pkts2 = check_slice!(pkts2, pkts2len);

    let cert1 = Cert::from_bytes(pkts1)?;
    let cert2 = Cert::from_bytes(pkts2)?;

    if cert1.fingerprint() != cert2.fingerprint() {
	return Err(Error::Fail("Can't merge different certificates".into()));
    }

    let (merged, updated)
	= cert1.clone().insert_packets(cert2.into_packets())?;

    let merged_bytes_;
    let (result, result_len) = if ! updated {
	// The certificate is unchanged.  Nevertheless,
	// Cert::from_bytes may have changed the bit representation,
	// e.g., by canonicalizing it.  To avoid making rpm think that
	// the certificate has changed when it hasn't (it does a
	// memcmp), we return pkts1.
	(pkts1.as_ptr(), pkts1len)
    } else {
	merged_bytes_ = merged.to_vec()?;
	(merged_bytes_.as_ptr(), merged_bytes_.len())
    };

    unsafe {
	let buffer = libc::malloc(result_len);
	libc::memcpy(buffer, result as *const c_void, result_len);

	*pktsmlen = result_len as size_t;
	*pktsm = buffer as *mut u8;
    }

    Ok(())
});


#[cfg(test)]
mod tests {
    use super::*;

    use openpgp::cert::CertBuilder;
    use openpgp::serialize::SerializeInto;
    use openpgp::types::KeyFlags;

    // Check that we can successfully merge two certificates.
    #[test]
    fn merge_certs() {
	let p = openpgp::policy::StandardPolicy::new();

	let (cert, _rev) = CertBuilder::new()
	    .add_userid("Alice")
	    .generate()
	    .unwrap();

	let vc = cert.with_policy(&p, None).unwrap();

	// We should only have a primary, which is certification capable.
	assert_eq!(vc.keys().for_signing().count(), 0);
	assert_eq!(vc.keys().for_transport_encryption().count(), 0);
	assert_eq!(vc.keys().for_storage_encryption().count(), 0);

	// Add a signing subkey.
	let cert2 = KeyBuilder::new(
	    KeyFlags::empty().set_signing())
	    .subkey(vc.clone()).unwrap()
	    .attach_cert().unwrap();

	// Add an encryption subkey.
	let cert3 = KeyBuilder::new(
	    KeyFlags::empty().set_transport_encryption())
	    .subkey(vc.clone()).unwrap()
	    .attach_cert().unwrap();

	let cert2_bytes = cert2.to_vec().unwrap();
	let cert3_bytes = cert3.to_vec().unwrap();

	let mut result: *mut u8 = std::ptr::null_mut();
	let mut result_len: size_t = 0;

	eprintln!("About to run pgpPubkeyMerge");
	let ec = _pgpPubkeyMerge(
	    cert2_bytes.as_ptr(), cert2_bytes.len(),
	    cert3_bytes.as_ptr(), cert3_bytes.len(),
	    &mut result, &mut result_len,
	    0);

	assert_eq!(ec, 0);

	assert!(! result.is_null());
        let result = unsafe {
	    std::slice::from_raw_parts(result as *const u8, result_len)
	};

	let result = Cert::from_bytes(result).expect("valid cert");

	assert_eq!(cert.fingerprint(), result.fingerprint());
	assert!(result != cert);
	assert!(result != cert2);
	assert!(result != cert3);

	let expected = cert2.clone().merge_public(cert3.clone()).unwrap();
	assert_eq!(result, expected);

	let result_vc = result.with_policy(&p, None).unwrap();

	assert_eq!(result_vc.keys().for_signing().count(), 1);
	assert_eq!(result_vc.keys().for_transport_encryption().count(), 1);
	assert_eq!(result_vc.keys().for_storage_encryption().count(), 0);
    }

    // Check that when we attempt to merge two different certificates,
    // we return an error.
    #[test]
    fn merge_certs_mismatch() {
	let (cert, _rev) = CertBuilder::new()
	    .add_userid("Alice")
	    .generate()
	    .unwrap();
	let (cert2, _rev) = CertBuilder::new()
	    .add_userid("Bob")
	    .generate()
	    .unwrap();

	let cert_bytes = cert.to_vec().unwrap();
	let cert2_bytes = cert2.to_vec().unwrap();

	let mut result: *mut u8 = std::ptr::null_mut();
	let mut result_len: size_t = 0;

	eprintln!("About to run pgpPubkeyMerge");
	let ec = _pgpPubkeyMerge(
	    cert_bytes.as_ptr(), cert_bytes.len(),
	    cert2_bytes.as_ptr(), cert2_bytes.len(),
	    &mut result, &mut result_len,
	    0);

	assert_ne!(ec, 0);
    }
}
