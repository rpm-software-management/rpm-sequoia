// This is a reimplementation of rpm/rpmio/digest_openssl.c /
// rpm/rpmio/digest_libgcrypt.c using Sequoia.

use std::env;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::PathBuf;

use libc::{
    c_int,
    size_t,
};

use sequoia_openpgp as openpgp;
use openpgp::types::HashAlgorithm;
use openpgp::crypto::hash::Digest;

use crate::Error;
use crate::Result;

#[derive(Clone)]
pub struct DigestContext {
    pub(crate) ctx: Box<dyn Digest>,
}

impl DigestContext {
    pub(crate) fn digest_size(&self) -> usize {
        self.ctx.digest_size()
    }

    pub(crate) fn update<T: AsRef<[u8]>>(&mut self, data: T) {
        self.ctx.update(data.as_ref());
    }

    pub(crate) fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
        Ok(self.ctx.digest(digest)?)
    }

    pub(crate) fn into_digest(self) -> Result<Vec<u8>> {
        Ok(self.ctx.into_digest()?)
    }
}

const CRYPTO_POLICY: &'static str
    = "/etc/crypto-policies/back-ends/sequoia.config";

ffi!(
/// int rpmInitCrypto(void)
fn _rpmInitCrypto() -> Binary {
    let crypto_policy = if let Ok(f) = env::var("RPM_SEQUOIA_CONFIG") {
        if f.is_empty() {
            // Empty means don't read anything.
            return Ok(());
        } else {
            PathBuf::from(f)
        }
    } else {
        PathBuf::from(CRYPTO_POLICY)
    };

    let mut f = match File::open(&crypto_policy) {
        Ok(f) => f,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            // There is no configuration.  That's fine.
            return Ok(());
        }
        Err(err) => {
            eprintln!("Error opening {:?}: {}", crypto_policy, err);
            return Err(anyhow::anyhow!(
                "Error opening {:?}: {}", crypto_policy, err).into());
        }
    };

    let mut config = Vec::new();
    if let Err(err) = f.read_to_end(&mut config) {
        eprintln!("Error reading {:?}: {}",
                  crypto_policy, err);
        return Err(anyhow::anyhow!(
            "Error reading {:?}: {}", crypto_policy, err).into());
    }

    let mut p = sequoia_policy_config::ConfiguredStandardPolicy::new();
    if let Err(err) = p.from_bytes(config) {
        eprintln!("Error parsing {:?}: {}", crypto_policy, err);
        return Err(anyhow::anyhow!(
            "Error parsing {:?}: {}", crypto_policy, err).into());
    }

    let p = p.build();

    *crate::P.write().unwrap() = p;

    Ok(())
});

ffi!(
/// int rpmFreeCrypto(void)
fn _rpmFreeCrypto() -> Binary {
    Ok(())
});

ffi!(
/// DIGEST_CTX rpmDigestInit(int hashalgo, rpmDigestFlags flags)
///
/// rpmDigestFlags currently does not define any flags.
fn _rpmDigestInit(hashalgo: c_int, flags: c_int) -> *mut DigestContext {
    if hashalgo < 0 || hashalgo > u8::MAX as c_int {
        return Err(Error::Fail("Out of range".into()));
    }
    let hashalgo = HashAlgorithm::from(hashalgo as u8);

    if flags != 0 {
        return Err(Error::Fail(format!("Unsupported flags: {}", flags)));
    }

    let ctx = DigestContext {
        ctx: hashalgo.context()?,
    };

    Ok(move_to_c!(ctx))
});

ffi!(
/// DIGEST_CTX rpmDigestDup(DIGEST_CTX octx)
fn _rpmDigestDup(ctx: *const DigestContext) -> *mut DigestContext {
    let ctx = check_ptr!(ctx);
    Ok(Box::into_raw(Box::new(ctx.clone())))
});

ffi!(
/// size_t rpmDigestLength(int hashalgo)
fn _rpmDigestLength(hashalgo: c_int) -> size_t[0] {
    if hashalgo < 0 || hashalgo > u8::MAX as c_int {
        return Ok(0);
    }
    let hashalgo = HashAlgorithm::from(hashalgo as u8);

    use HashAlgorithm::*;
    let len = match hashalgo {
        MD5 => 16,
        SHA1 => 20,
        RipeMD => 20,
        SHA256 => 32,
        SHA384 => 48,
        SHA512 => 64,
        SHA224 => 28,
        _ => 0,
    };

    Ok(len)
});

ffi!(
/// int rpmDigestUpdate(DIGEST_CTX ctx, const void * data, size_t len)
fn _rpmDigestUpdate(ctx: *mut DigestContext,
                    data: *const u8, len: size_t) -> ErrorCode {
    let ctx = check_mut!(ctx);
    let data = check_slice!(data, len);

    ctx.update(data);

    Ok(())
});

ffi!(
/// int rpmDigestFinal(DIGEST_CTX ctx, void ** datap, size_t *lenp, int asAscii)
fn _rpmDigestFinal(ctx: *mut DigestContext,
                   datap: *mut *mut u8, lenp: *mut size_t,
                   as_ascii: c_int) -> Binary
{
    let ctx = claim_from_c!(ctx);
    let datap = check_optional_mut!(datap);
    let lenp = check_optional_mut!(lenp);

    let mut digest = ctx.into_digest()?;

    if as_ascii != 0 {
        digest = digest
            .iter()
            .map(|x| {
                let x = format!("{:02x}", x);
                let x = x.as_bytes();
                std::iter::once(x[0]).chain(std::iter::once(x[1]))
            })
            .flatten()
            // Add a NUL.
            .chain(std::iter::once(0))
            .collect();
    }

    digest.shrink_to_fit();
    if let Some(lenp) = lenp {
        *lenp = digest.len() as size_t;
    }
    if let Some(datap) = datap {
        *datap = digest.as_mut_ptr();
        // Pass ownership to the caller.
        std::mem::forget(digest);
    }

    Ok(())
});
