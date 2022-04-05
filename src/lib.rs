#[allow(unused_imports)]
use anyhow::Context;

use libc::c_int;

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
    #[error("Failure: {0}")]
    Fail(String),
}


impl From<Error> for ErrorCode {
    fn from(err: Error) -> ErrorCode {
        match err {
            Error::Ok => 0,
            Error::Fail(_) => 2,
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Error {
        Error::Fail(format!("{}", err))
    }
}

// Wraps an ffi function, which returns an arbitrary type.
//
// The inner function returns `Result<$rt>`.  This wrapper maps
// `Ok($rt)` to `$Crt` using `$rt_to_crt` and `Err(err)` to
// `$err_to_crt`.
macro_rules! ffi {
    // $Crt is the C function's return type.  It must be possible to
    // convert an Error value v of type $rt to a value of type $Crt by doing:
    // $Crt::from($rt).
    //
    // $ok is the value (of type $rt) to map Ok to.
    (fn $f:ident($($v:ident: $t:ty),*)
        -> Result<$rt:ty, $et:ty>
        -> ($Crt:ty; $rt_to_crt:expr; $err_to_crt: expr)
        $body:block
     ) =>
    {
        // The wrapper.  It calls $f and turns the result into an
        // error code.
        #[allow(unused)]
        #[no_mangle] pub extern "C"
        fn $f($($v: $t),*) -> $Crt {
            // The actual function.
            let inner = |$($v: $t),*| -> std::result::Result<$rt, $et> { $body };

            match inner($($v,)*) {
                Ok(v) => {
                    // XXX: Replace this line with a panic! and the ICE goes away.
                    let rt: $Crt = $rt_to_crt(v);
                    rt
                    // panic!();
                }
                Err(err) => {
                    let rt: $Crt = $err_to_crt(err);
                    rt
                }
            }
        }
    }
}

// #[allow(unused)]
// #[no_mangle] pub extern "C"
// fn pgpSignatureType(dig: *const c_int) -> c_int {
//     // The actual function.
//     fn inner(dig: *const c_int) -> std::result::Result<c_int, crate::Error> { panic!(); }
// 
//     // We use AssertUnwindSafe.  This is safe, because if we
//     // catch a panic, we abort.  If we turn the panic into an
//     // error, then we need to reexamine this assumption.
//     let r = std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
//         match inner(dig) {
//             Ok(v) => {
//                 let rt_to_crt = |v| { v };
//                 let rt: c_int = rt_to_crt(v);
//                 rt
//             }
//             Err(err) => {
//                 let err_to_crt = |_| -1;
//                 let rt: c_int = err_to_crt(err);
//                 rt
//             }
//         }
//     }));
//     match r {
//         Ok(code) => code,
//         Err(_) => {
//             unsafe { ::libc::abort() };
//         }
//     }
// }

ffi!(fn pgpSignatureType(dig: *const c_int)
     -> Result<c_int, crate::Error>
     -> (c_int;
         |v| {
             v
         };
         |_| -1)
{
    panic!();
});
