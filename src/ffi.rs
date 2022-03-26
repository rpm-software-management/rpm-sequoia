// Wraps an ffi function, which returns an arbitrary type.
//
// The inner function returns `Result<$rt>`.  This wrapper maps
// `Ok($rt)` to `$Crt` using `$rt_to_crt` and `Err(err)` to
// `$err_to_crt`.
macro_rules! ffi {
    // Wraps an ffi function, which returns 0 on success and -1 on error.
    (fn $f:ident($($v:ident: $t:ty),*) -> Binary $body:block) =>
    {
        ffi!(fn $f($($v: $t),*)
                   -> Result<(), crate::Error>
                   -> (crate::ErrorCode;
                       |_| 0;
                       |_err| -1)
             {
                 $body
             });
    };

    // Wraps an ffi function, which returns an RC.
    (fn $f:ident($($v:ident: $t:ty),*) -> ErrorCode $body:block) =>
    {
        ffi!(fn $f($($v: $t),*)
                   -> Result<(), crate::Error>
                   -> (crate::ErrorCode;
                       |_| 0;
                       |err| crate::ErrorCode::from(err))
             {
                 $body
             });
    };

    // Wraps an ffi function, which returns a PgpArmorError.
    (fn $f:ident($($v:ident: $t:ty),*) -> PgpArmor $body:block) =>
    {
        ffi!(fn $f($($v: $t),*)
                   -> Result<crate::rpm::PgpArmor, crate::rpm::PgpArmorError>
                   -> (crate::ErrorCode;
                       |v: crate::rpm::PgpArmor| {
                           t!("-> {:?}", v);
                           v.into()
                       };
                       |err: crate::rpm::PgpArmorError| err.into())
             {
                 $body
             });
    };

    // Wraps an ffi function, which returns an object whose type is
    // *const T.  Returns NULL on error.
    (fn $f:ident($($v:ident: $t:ty),*) -> *const $value:ty $body:block) =>
    {
        ffi!(fn $f($($v: $t),*)
                   -> Result<*const $value, crate::Error>
                   -> (*const $value;
                       |v| v;
                       |_| std::ptr::null())
             {
                 $body
             });
    };

    // Wraps an ffi function, which returns an object whose type is
    // *mut T.  Returns NULL on error.
    (fn $f:ident($($v:ident: $t:ty),*) -> *mut $value:ty $body:block) =>
    {
        ffi!(fn $f($($v: $t),*)
                   -> Result<*mut $value, crate::Error>
                   -> (*mut $value;
                       |v| v;
                       |_| std::ptr::null_mut())
             {
                 $body
             });
    };

    // Wraps an ffi function, which returns a value.  The value is passed
    // through as is and errors are mapped to `$err`.
    (fn $f:ident($($v:ident: $t:ty),*) -> $value:ty[$err:expr] $body:block) =>
    {
        ffi!(fn $f($($v: $t),*)
                   -> Result<$value, crate::Error>
                   -> ($value;
                       |v| {
                           t!(" -> {:?}", v);
                           v
                       };
                       |_| $err)
             {
                 $body
             });
    };

    // Wraps an ffi function, which returns void.
    //
    // The inner function returns `Result<()>` and this is mapped to `()`.
    //
    // Note: inner body returns Ok(()) by default.
    (fn $f:ident($($v:ident: $t:ty),*) $body:block) =>
    {
        ffi!(fn $f($($v: $t),*)
             -> Result<(), crate::Error>
             -> (();
                 |_| ();
                 |_| ())
             {
                 let () = $body;
                 Ok(())
             });
    };


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
        #[no_mangle] pub extern "C"
        fn $f($($v: $t),*) -> $Crt {
            tracer!(*crate::TRACE, stringify!($f));

            // The actual function.
            fn inner($($v: $t),*) -> std::result::Result<$rt, $et> { $body }

            t!("entered");
            // We use AssertUnwindSafe.  This is safe, because if we
            // catch a panic, we abort.  If we turn the panic into an
            // error, then we need to reexamine this assumption.
            let r = std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                match inner($($v,)*) {
                    Ok(v) => {
                        t!("-> success");
                        let rt: $Crt = $rt_to_crt(v);
                        rt
                    }
                    Err(err) => {
                        t!("-> error: {}{}",
                           err,
                           {
                               use std::error::Error;

                               let mut causes = String::new();
                               let mut cause = err.source();
                               while let Some(e) = cause {
                                   causes.push_str("\n  because: ");
                                   causes.push_str(&e.to_string());
                                   cause = e.source();
                               }
                               causes
                           });

                        let rt: $Crt = $err_to_crt(err);
                        rt
                    }
                }
            }));
            match r {
                Ok(code) => code,
                Err(_) => {
                    t!("-> panic!");
                    unsafe { ::libc::abort() };
                }
            }
        }
    }
}

// Creates a stub for a ffi, which returns an error.
#[allow(unused_macros)]
macro_rules! stub {
    ($f:ident) => {
        #[no_mangle] pub extern "C"
        fn $f() -> crate::ErrorCode {
            tracer!(*crate::TRACE, stringify!($f));
            t!("{} is a stub", stringify!($f));
            crate::Error::Fail(
                format!("Unimplemented: {}", stringify!($f))).into()
        }
    };
}

// Checks if a `*const T` pointer is NULL if so, returns an error.
// Otherwise, returns `&T`.
macro_rules! check_ptr {
    ($p:ident) => {{
        let p: *const _ = $p;
        if p.is_null() {
            return Err(Error::Fail(
                format!("{} must not be NULL", stringify!($p))).into());
        } else {
            t!("{}: & <- {:?}", stringify!($p), $p);
            unsafe { &*p }
        }
    }}
}

// Returns an Option<&T> from a *const T.
macro_rules! check_optional_ptr {
    ($p:ident) => {{
        let p: *const _ = $p;
        if p.is_null() {
            None
        } else {
            t!("{}: Option<&> <- {:?}", stringify!($p), $p);
            Some(unsafe { &*p })
        }
    }}
}

// Checks if a `*mut T` pointer is NULL if so, returns an error.
// Otherwise, returns `&mut T`.
macro_rules! check_mut {
    ($p:ident) => {{
        let p: *mut _ = $p;
        if p.is_null() {
            return Err(Error::Fail(
                format!("{} must not be NULL", stringify!($p))).into());
        } else {
            t!("{}: &mut <- {:?}", stringify!($p), $p);
            unsafe { &mut *p }
        }
    }}
}

// Returns an Option<&mut T> from a *mut T.
macro_rules! check_optional_mut {
    ($p:ident) => {{
        let p: *mut _ = $p;
        if p.is_null() {
            None
        } else {
            t!("{}: Option<&mut> <- {:?}", stringify!($p), $p);
            Some(unsafe { &mut *p })
        }
    }}
}

// Checks if a `*const T` pointer is NULL if so, returns an error.
// Otherwise, returns a slice `&[T]` with `l` elements.
macro_rules! check_slice {
    ($p:ident, $l:expr) => {
        if $p.is_null() {
            return Err(Error::Fail(
                format!("{} must not be NULL", stringify!($p))));
        } else {
            t!("{}: &[] <- {:?}", stringify!($p), $p);
            unsafe { std::slice::from_raw_parts($p as *const u8, $l) }
        }
    }
}

// Checks if a `*mut T` pointer is NULL if so, returns an error.
// Otherwise, returns a slice `&mut [T]` with `l` elements.
macro_rules! check_mut_slice {
    ($p:ident, $l:expr) => {{
        let p: *mut _ = $p;
        if p.is_null() {
            return Err(Error::Fail(
                format!("{} must not be NULL", stringify!($p))));
        } else {
            t!("{}: &[] <- {:?}", stringify!($p), p);
            unsafe { std::slice::from_raw_parts_mut($p as *mut u8, $l) }
        }
    }}
}

// Checks if a `*const c_char` pointer is NULL if so, returns an
// error.  Otherwise, returns a CStr.
macro_rules! check_cstr {
    ($s:ident) => {{
        let _: *const libc::c_char = $s;
        let s = check_ptr!($s);
        unsafe { std::ffi::CStr::from_ptr(s) }
    }}
}

// Moves ownership of a parameter of type T to C.
//
// Given a T, returns a *mut T.
macro_rules! move_to_c {
    ($expr:expr) => {{
        let p = Box::into_raw(Box::new($expr));
        t!("{}: returning {:?}", stringify!($expr), p);
        p
    }}
}

// Moves ownership of an object owned by C.
//
// This is the opposite of move_to_c.
macro_rules! claim_from_c {
    ($p:ident) => {{
        if $p.is_null() {
            return Err(Error::Fail(
                format!("{} must not be NULL", stringify!($p))));
        }
        unsafe {
            t!("{}: owned <- {:?}", stringify!($p), $p);
            Box::from_raw($p)
        }
    }};
}

// Moves ownership of a parameter of type Option<T> to C.
macro_rules! move_option_to_c {
    ($expr:expr) => {
        $expr.map(|x| box_raw!(x)).unwrap_or(::std::ptr::null_mut())
    }
}

/// Transfers ownership from C to Rust, then frees the object.
///
/// NOP if called with NULL.
macro_rules! free {
    ($p:ident) => {{
        if let Some(ptr) = $p {
            let ptr = unsafe { Box::from_raw(ptr) };
            drop(ptr);
        }
    }};
}
