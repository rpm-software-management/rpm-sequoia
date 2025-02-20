use libc::c_int;

use sequoia_openpgp as openpgp;
use openpgp::armor;

// We use Error rather than anyhow's error so that we force the
// function to convert the error into a form that we can easily pass
// back to the engine.
pub type Result<T> = std::result::Result<T, Error>;

pub type ErrorCode = c_int;

#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone)]
#[allow(unused)]
pub enum Error {
    #[error("Success")]
    Ok,
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Failure: {0}")]
    Fail(String),
    #[error("Signature is OK, but key is not trusted: {0}")]
    NotTrusted(String),
    #[error("Public key is unavailable: {0}")]
    NoKey(String),
}

impl From<Error> for ErrorCode {
    fn from(err: Error) -> ErrorCode {
        match err {
            Error::Ok => 0,
            Error::NotFound(_) => 1,
            Error::Fail(_) => 2,
            Error::NotTrusted(_) => 3,
            Error::NoKey(_) => 4,
        }
    }
}

impl From<ErrorCode> for Error {
    fn from(err: ErrorCode) -> Error {
        match err {
            0 => Error::Ok,
            1 => Error::NotFound("<unspecified>".into()),
            2 => Error::Fail("<unspecified>".into()),
            3 => Error::NotTrusted("<unspecified>".into()),
            4 => Error::NoKey("<unspecified>".into()),

            _ => Error::Fail("<unspecified>".into()),
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Error {
        Error::Fail(format!("{}", err))
    }
}

#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone)]
#[allow(unused)]
pub enum PgpArmorError {
    #[error("Success")]
    Ok,

    #[error("unknown error")]
    UnknownError,

    #[error("armor crc check")]
    CrcCheck,
    #[error("armor body decode")]
    BodyDecode,
    #[error("armor crc decode")]
    CrcDecode,
    #[error("armor no end pgp")]
    NoEndPgp,
    #[error("armor unknown preamble tag")]
    UnknownPreambleTag,
    #[error("armor unknown armor type")]
    UnknownArmorType,
    #[error("armor no begin pgp")]
    NoBeginPgp,
}

impl From<PgpArmorError> for ErrorCode {
    fn from(err: PgpArmorError) -> ErrorCode {
        match err {
            PgpArmorError::Ok => 0,
            PgpArmorError::UnknownError => -1,
            PgpArmorError::CrcCheck => -7,
            PgpArmorError::BodyDecode => -6,
            PgpArmorError::CrcDecode => -5,
            PgpArmorError::NoEndPgp => -4,
            PgpArmorError::UnknownPreambleTag => -3,
            PgpArmorError::UnknownArmorType => -2,
            PgpArmorError::NoBeginPgp => -1,
        }
    }
}

impl From<Error> for PgpArmorError {
    fn from(_err: Error) -> PgpArmorError {
        PgpArmorError::UnknownError
    }
}

impl From<anyhow::Error> for PgpArmorError {
    fn from(_err: anyhow::Error) -> PgpArmorError {
        PgpArmorError::UnknownError
    }
}

#[non_exhaustive]
#[allow(unused)]
#[derive(Debug, Clone)]
pub enum PgpArmor {
    None,
    Message,
    Pubkey,
    Signature,
    SignedMessage,
    File,
    Privkey,
    Seckey,
}

impl From<PgpArmor> for c_int {
    fn from(a: PgpArmor) -> c_int {
        match a {
            PgpArmor::None => 0,
            PgpArmor::Message => 1,
            PgpArmor::Pubkey => 2,
            PgpArmor::Signature => 3,
            PgpArmor::SignedMessage => 4,
            PgpArmor::File => 5,
            PgpArmor::Privkey => 6,
            PgpArmor::Seckey => 7,
        }
    }
}

impl From<c_int> for PgpArmor {
    fn from(a: c_int) -> PgpArmor {
        match a {
            0 => PgpArmor::None,
            1 => PgpArmor::Message,
            2 => PgpArmor::Pubkey,
            3 => PgpArmor::Signature,
            4 => PgpArmor::SignedMessage,
            5 => PgpArmor::File,
            6 => PgpArmor::Privkey,
            7 => PgpArmor::Seckey,
            _ => PgpArmor::None,
        }
    }
}

impl TryFrom<PgpArmor> for armor::Kind {
    type Error = Error;

    fn try_from(a: PgpArmor) -> Result<armor::Kind> {
        let err = || Err(Error::Fail(format!("Unsupported armor type: {:?}", a)));
        match a {
            PgpArmor::None => err(),
            PgpArmor::Message => Ok(armor::Kind::Message),
            PgpArmor::Pubkey => Ok(armor::Kind::PublicKey),
            PgpArmor::Signature => Ok(armor::Kind::Signature),
            PgpArmor::SignedMessage => err(),
            PgpArmor::File => Ok(armor::Kind::File),
            PgpArmor::Privkey => err(),
            PgpArmor::Seckey => Ok(armor::Kind::SecretKey),
        }
    }
}

impl From<Option<armor::Kind>> for PgpArmor {
    fn from(k: Option<armor::Kind>) -> PgpArmor {
        use armor::Kind::*;

        match k {
            None => PgpArmor::None,
            Some(Message) => PgpArmor::Message,
            Some(PublicKey) => PgpArmor::Pubkey,
            Some(SecretKey) => PgpArmor::Seckey, // XXX: PgpArmor::Privkey
            Some(Signature) => PgpArmor::Signature, // XXX: PgpArmor::SignedMessage
            Some(File) => PgpArmor::File,
            _ => PgpArmor::File, // XXX
        }
    }
}
