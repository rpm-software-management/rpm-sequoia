use std::env;
use std::ffi::{
    CString,
};
use std::fmt::Debug;
use std::io::Read;
use std::io::Write;
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
    size_t,
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
use openpgp::parse::{PacketParser, PacketParserResult};
use openpgp::parse::Parse;
use openpgp::policy::{
    NullPolicy,
    Policy,
};
use openpgp::types::RevocationStatus;

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

//pub const P: &StandardPolicy = &StandardPolicy::new();
pub const P: &NullPolicy = &NullPolicy::new();

// Set according to the RPM_TRACE environment variable (enabled if
// non-zero), or if we are built in debug mode.
lazy_static::lazy_static! {
    static ref TRACE: bool = {
        if let Ok(v) = env::var("RPM_TRACE") {
            let v: isize = v.parse().unwrap_or(1);
            v != 0
        } else if cfg!(debug_assertions) {
            true
        } else {
            false
        }
    };
}

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

// Not yet implemented.
stub!(pgpNewDig);
stub!(pgpFreeDig);
stub!(pgpDigGetParams);
stub!(pgpPrtPkts);


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

// Returns the signature's type.
//
// If `dig` is NULL or does not contain a signature, then this
// function returns -1.
ffi!(fn pgpSignatureType(dig: *const PgpDigParams) -> c_int[-1] {
    let dig = check_ptr!(dig);

    dig.signature()
        .ok_or_else(|| Error::Fail("Not a signature".into()))
        .map(|sig| {
            u8::from(sig.typ()).into()
        })
});

// This technically returns void, but returning an error to C will be
// fine.
ffi!(fn pgpDigParamsFree(dig: Option<&mut PgpDigParams>) {
    free!(dig);
});

// "Compares" the two parameters and returns 1 if they differ and 0 if
// they match.
//
// Two signatures are considered the same if they have the same
// parameters (version, signature type, public key and hash
// algorithms, and the first issuer packet).  Note: this function
// explicitly does not check that the MPIs are the same, nor that the
// signature creation time is the same!  This is intended.  The only
// use of this function in the rpm code base is to check whether a key
// has already made a signature (cf. sign/rpmgensig.c:haveSignature).
//
// Two certificates are considered the same if they have the same
// fingerprint.  (rpm does not currently use this functionality.)
//
// Two subkeys are considered the same if they have the same
// fingerprint.  (rpm does not currently use this functionality.)
ffi!(fn pgpDigParamsCmp(p1: *const PgpDigParams,
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

// Returns the object's public key or algorithm algorithm.
//
// `algotype` is either `PGPVAL_PUBKEYALGO` or `PGPVAL_HASHALGO`.
// Other algo types are not support and cause this function to return
// 0.
ffi!(fn pgpDigParamsAlgo(dig: *const PgpDigParams,
                         algotype: c_uint) -> c_uint[0] {
    let dig = check_ptr!(dig);

    match (algotype, &dig.obj) {
        // pubkey algo.
        (PGPVAL_PUBKEYALGO, PgpDigParamsObj::Cert(cert)) => {
            Ok(u8::from(cert.primary_key().pk_algo()).into())
        }
        (PGPVAL_PUBKEYALGO, PgpDigParamsObj::Subkey(_, _)) => {
            Ok(u8::from(dig.key().expect("valid").pk_algo()).into())
        }
        (PGPVAL_PUBKEYALGO, PgpDigParamsObj::Signature(sig)) => {
            Ok(u8::from(sig.pk_algo()).into())
        }

        // hash algo.
        (PGPVAL_HASHALGO, PgpDigParamsObj::Cert(cert)) => {
            match cert.with_policy(P, None) {
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
            match ka.with_policy(P, None) {
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

// Returns the issuer or the Key ID.
//
// If `dig` is a signature, then this returns the Key ID stored in the
// first Issuer or Issuer Fingerprint subpacket as a hex string.
// (This is not authenticated.)
//
// If `dig` is a certificate or a subkey, then this returns the key's
// Key ID.
//
// The caller must not free the returned buffer.
ffi!(fn pgpDigParamsSignID(dig: *const PgpDigParams) -> *const u8 {
    let dig = check_ptr!(dig);
    Ok(dig.signid.as_ptr())
});

// Returns the primary User ID, if any.
//
// If `dig` is a signature, then this returns NULL.
//
// If `dig` is a certificate or a subkey, then this returns the
// certificate's primary User ID, if any.
//
// This interface does not provide a way for the caller to recognize
// any embedded NUL characters.
//
// The caller must not free the returned buffer.
ffi!(fn pgpDigParamsUserID(dig: *const PgpDigParams) -> *const c_char {
    let dig = check_ptr!(dig);
    if let Some(ref userid) = dig.userid {
        Ok(userid.as_ptr())
    } else {
        Ok(std::ptr::null())
    }
});

// Returns the object's version.
//
// If `dig` is a signature, then this returns the version of the
// signature packet.
//
// If `dig` is a certificate, then this returns the version of the
// primary key packet.
//
// If `dig` is a subkey, then this returns the version of the subkey's
// key packet.
ffi!(fn pgpDigParamsVersion(dig: *const PgpDigParams) -> c_int[0] {
    let dig = check_ptr!(dig);
    let version = match &dig.obj {
        PgpDigParamsObj::Cert(cert) => {
            cert.primary_key().version()
        }
        PgpDigParamsObj::Subkey(_, _) => {
            dig.key().unwrap().version()
        }
        PgpDigParamsObj::Signature(sig) => {
            sig.version()
        }
    };
    Ok(version as c_int)
});

// Returns the object's time.
//
// If `dig` is a signature, then this returns the signature's creation
// time.
//
// If `dig` is a certificate, then this returns the primary key's key
// creation time.
//
// If `dig` is a subkey, then this returns the subkey's key creation
// time.
ffi!(fn pgpDigParamsCreationTime(dig: *const PgpDigParams) -> u32[0] {
    let dig = check_ptr!(dig);
    let t = match &dig.obj {
        PgpDigParamsObj::Cert(cert) => {
            cert.primary_key().creation_time()
        }
        PgpDigParamsObj::Subkey(cert, fpr) => {
            cert.keys().subkeys()
                .key_handle(fpr)
                .next()
                .expect("subkey missing")
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

// Returns the signature's hash prefix as a big endian 16-bit number.
//
// The hash prefix is the first (most significant) two bytes of the
// signature's hash.  This function returns those two bytes.
//
// If `dig` is not a signature, then this returns 0.
ffi!(fn pgpDigParamsHashPrefix(dig: *const PgpDigParams) -> u16[0] {
    let dig = check_ptr!(dig);
    let p = match &dig.obj {
        PgpDigParamsObj::Cert(_cert) => {
            0
        }
        PgpDigParamsObj::Subkey(_cert, _fpr) => {
            0
        }
        PgpDigParamsObj::Signature(sig) => {
            let p = sig.digest_prefix();
            ((p[0] as u16) << 8) + (p[1] as u16)
        }
    };
    Ok(p)
});

// Verifies the signature.
//
// If `key` is NULL, then this computes the hash and checks it against
// the hash prefix.
//
// If `key` is not NULL, then this checks that the signature is
// correct.
//
// This function does not modify `ctx`.  Instead, it first duplicates
// `ctx` and then hashes the the meta-data into that context.
//
// This function fails if the signature is not valid, or the key is
// not valid.
//
// A signature is valid if:
//
//   - The signature is alive now (not created in the future, and not
//     yet expired)
//
//   - It is accepted by the policy.
//
// A key is valid if as of the signature creation time:
//
//   - The certificate is valid according to the policy.
//
//   - The certificate is alive
//
//   - The certificate is not revoke
//
//   - The key is alive
//
//   - The key is not revoke
//
//   - The key has the signing capability set.
ffi!(fn pgpVerifySignature(key: *const PgpDigParams,
                           sig: *const PgpDigParams,
                           ctx: *mut digest::DigestContext) -> ErrorCode {
    let key = check_optional_ptr!(key);
    let sig = check_ptr!(sig);
    // This function MUST NOT free or even change ctx.
    let mut ctx = check_mut!(ctx).clone();

    let sig = sig.signature().ok_or_else(|| {
        Error::Fail("sig is not a signature".into())
    })?;

    let sig_time = if let Some(t) = sig.signature_creation_time() {
        t
    } else {
        return Err(Error::Fail("signature invalid: no creation time".into()));
    };

    // Allow some clock skew.
    if let Err(err) = sig.signature_alive(None,  Duration::new(5 * 60, 0)) {
        return Err(Error::Fail(format!("signature invalid: {}", err)));
    }

    if let Err(err) = P.signature(sig, Default::default()) {
        return Err(Error::Fail(
            format!("signature invalid: policy violation: {}", err)));
    }

    if let Some(key) = key {
        // Actually verify the signature.
        let cert = key.cert().ok_or_else(|| {
            Error::Fail("key is not a cert".into())
        })?;

        // We evaluate the certificate as of the signature creation
        // time.
        let vc = cert.with_policy(P, sig_time)?;

        if let Err(err) = vc.alive() {
            return Err(Error::Fail(
                format!("key invalid: not alive: {}", err)));
        }
        if let RevocationStatus::Revoked(_) = vc.revocation_status() {
            return Err(Error::Fail(
                format!("key invalid: certificate is revoked")));
        }

        // XXX: rpm only cares about the first issuer
        // subpacket.
        let issuer = match sig.get_issuers().into_iter().next() {
            Some(issuer) => issuer,
            None => return Err(Error::Fail("No issuer".into())),
        };

        // Find the key.
        match vc.keys()
            .alive()
            .revoked(false)
            .for_signing()
            .key_handle(issuer.clone())
            .next()
        {
            Some(key) => {
                // Finally we can verify the signature.
                sig.clone().verify_hash(&key, ctx.ctx.clone())?;
                return Ok(());
            }
            None => {
                return Err(Error::Fail(
                    format!("Cert does not contain key {} or it is not valid",
                            issuer)));
            }
        }
    } else {
        // We don't have a key, but we still check that the prefix is
        // correct.

        // These traits should be imported only where needed to avoid
        // bugs.
        use openpgp::serialize::Marshal;
        use openpgp::serialize::MarshalInto;

        // Hash the signature into the context.
        if sig.version() != 4 {
            return Err(Error::Fail(
                format!("Unsupported signature version: {}", sig.version())));
        }

        // See https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.4
        let mut sig_data = Vec::with_capacity(128);

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
        }

        return Err(Error::NoKey("Not provided".into()));
    }
});

// Returns the Key ID of the public key or the secret key stored in
// `pkt`.
//
// Returns -1 if `pkt` is not a public key or secret key.
//
// Note: this function does not handle public subkeys or secret
// subkeys!
//
// `keyid` was allocated by the caller and points to at least 8 bytes.
//
// Returns 0 on success and -1 on failure.
ffi!(fn pgpPubkeyKeyID(pkt: *const u8, pktlen: size_t, keyid: *mut u8)
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

    if let Some(k) = k {
        let buffer = check_mut_slice!(keyid, 8);
        buffer.copy_from_slice(k.as_bytes());

        Ok(())
    } else {
        Err(Error::Fail("Not a key".into()))
    }
});

// Wraps the data in ascii armor.
//
// `atype` is the armor type.
//
// The caller must free the returned buffer.
//
// Returns NULL on failure.
ffi!(fn pgpArmorWrap(atype: c_int, s: *const c_char, ns: size_t)
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

// Returns the length of the certificate in bytes.
//
// `pkts` points to a buffer.  This fails if `pkts` does not point to
// exactly one valid OpenPGP certificate.
//
// Returns 0 on failure.
ffi!(fn pgpPubKeyCertLen(pkts: *const u8, pktslen: size_t,
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

// Parses OpenPGP data.
//
// If `pkts` contains a signature and `pkttype` is 0 or
// `Tag::Signature`, this returns a `PgpDigParams` containing a
// signature.
//
// If `pkts` contains a certificate and `pkttype` is 0,
// `Tag::PublicKey`, or `Tag::SecretKey`, this returns a
// `PgpDigParams` containing a certificate.  The certificate is
// checked for validity in the sense that it only contains packets
// that belong to a certificate; this function does not check the
// binding signatures, etc.
//
// Returns 0 on success, -1 on failure.
ffi!(fn pgpPrtParams(pkts: *const u8, pktlen: size_t,
                     pkttype: c_uint, paramsp: *mut *mut PgpDigParams)
    -> Binary
{
    let pkttype: Option<Tag> = if pkttype == 0 {
        None
    } else {
        Some(Tag::from(pkttype as u8))
    };

    let pkts = check_slice!(pkts, pktlen);
    let paramsp = check_mut!(paramsp);
    *paramsp = std::ptr::null_mut();

    let ppr = PacketParser::from_bytes(pkts)?;

    let (obj, issuer, userid) = if let PacketParserResult::Some(ref pp) = ppr {
        // Process the packet.
        match pp.packet {
            Packet::Signature(ref sig)
                if pkttype.is_none() || pkttype == Some(Tag::Signature) =>
            {
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
                let cert = CertParser::from(ppr)
                    .next()
                    .ok_or(Error::Fail("Not an OpenPGP message".into()))??;

                let keyid = cert.keyid().as_bytes().to_vec();

                let userid = if let Ok(vc) = cert.with_policy(P, None) {
                    vc.primary_userid()
                        .ok()
                        .and_then(|u| {
                            CString::new(u.value()).ok()
                        })
                } else {
                    None
                };

                (PgpDigParamsObj::Cert(cert),
                 Some(keyid),
                 userid)
            }
            ref p => {
                return Err(Error::Fail(format!("{}", p.tag())));
            }
        }
    } else {
        return Err(Error::Fail("Not an OpenPGP message".into()));
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
});

// Returns a `PgpDigParams` data structure for each subkey.
ffi!(fn pgpPrtParamsSubkeys(pkts: *const u8, pktlen: size_t,
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

    let userid = if let Ok(vc) = cert.with_policy(P, None) {
        vc.primary_userid()
            .ok()
            .and_then(|u| {
                CString::new(u.value()).ok()
            })
    } else {
        None
    };

    // We return all subkeys here.  Subkeys are checked for validity
    // on demand.
    let mut keys: Vec<*mut PgpDigParams> = cert
        .keys().subkeys()
        .map(|ka| {
            let zeros = [0; 8];
            let mut dig = PgpDigParams {
                obj: PgpDigParamsObj::Subkey(cert.clone(), ka.fingerprint()),
                signid: zeros,
                userid: userid.clone(),
            };
            dig.signid.copy_from_slice(ka.keyid().as_bytes());
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

// Strips the armor armor and returns the decoded data in `pkt`.
//
// Despite its name, this function does not actually parse any OpenPGP
// packets; it just strips the ascii armor encoding.
//
// Returns the type of armor on success (>0) or an error code
// indicating the type of failure (<0).
ffi!(fn pgpParsePkts(armor: *const c_char,
                     pkt: *mut *mut c_char, pktlen: *mut size_t)
     -> PgpArmor
{
    let armor = check_cstr!(armor);
    let pkt = check_mut!(pkt);
    *pkt = std::ptr::null_mut();
    let pktlen = check_mut!(pktlen);

    let mut reader = armor::Reader::new(
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

// Lints the first certificate in pkts.
ffi!(fn pgpPubkeyLint(pkts: *const c_char,
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
        match cert.with_policy(P, None) {
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
                    break 'done false;
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
                    break 'done false;
                }
            }
        };

        let mut have_signing = false;
        for ka in cert.keys() {
            let keyid = ka.keyid();

            match ka.with_policy(P, None) {
                Err(err) => {
                    lint(&format!("Policy rejects subkey {}: {}",
                                  keyid, err));
                    continue;
                }
                Ok(ka) => {
                    if ! ka.for_signing() {
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

                    if ! ka.pk_algo().is_supported() {
                        lint(&format!("Subkey {} is not supported \
                                       (no support for {})",
                                      keyid,
                                      ka.pk_algo()));
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
