use libc::c_int;

// XXX: Remove '; $err_to_crt:expr' and the ICE goes away.
//
// -> ($Crt:ty; $rt_to_crt:expr)
macro_rules! ffi {
    (fn $f:ident()
        -> Result<$rt:ty, $et:ty>
        -> ($Crt:ty; $rt_to_crt:expr; $err_to_crt:expr)
        $body:block
     ) =>
    {
        #[no_mangle] pub extern "C"
        fn $f() -> $Crt {
            // XXX: OR Replace this line with 0 and the ICE goes away.
            let rt: $Crt = $rt_to_crt(1i32);
            rt
            // 0
        }
    }
}

fn id(v: c_int) -> c_int { v }

ffi!(fn pgpSignatureType()
     -> Result<c_int, crate::Error>
     -> (c_int;
         // XXX: OR: Replace this closure with a function:
         |v| -> c_int { v };
         // id;
         |_| -1)
{
    panic!();
});
