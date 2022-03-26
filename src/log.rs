use std::cell::RefCell;

// Like eprintln!
macro_rules! log {
    ($dst:expr $(,)?) => (
        eprintln!("{}", $dst)
    );
    ($dst:expr, $($arg:tt)*) => (
        eprintln!("{}", std::format!($dst, $($arg)*))
    );
}

// The indent level.  It is increased with each call to tracer and
// decremented when the tracker goes out of scope.
thread_local! {
    pub static INDENT_LEVEL: RefCell<usize> = RefCell::new(0);
}

// Like eprintln!, but the first argument is a boolean, which
// indicates if the string should actually be printed.
macro_rules! trace {
    ( $TRACE:expr, $fmt:expr, $($pargs:expr),* ) => {
        if $TRACE {
            let indent_level = crate::log::INDENT_LEVEL.with(|i| {
                *i.borrow()
            });

            let ws = "                                                  ";

            log!("{}{}",
                 &ws[0..std::cmp::min(ws.len(), std::cmp::max(1, indent_level) - 1)],
                 format!($fmt, $($pargs),*));
        }
    };
    ( $TRACE:expr, $fmt:expr ) => {
        trace!($TRACE, $fmt, );
    };
}

macro_rules! tracer {
    ( $TRACE:expr, $func:expr ) => {
        // Currently, Rust doesn't support $( ... ) in a nested
        // macro's definition.  See:
        // https://users.rust-lang.org/t/nested-macros-issue/8348/2
        macro_rules! t {
            ( $fmt:expr ) =>
            { trace!($TRACE, "{}: {}", $func, $fmt) };
            ( $fmt:expr, $a:expr ) =>
            { trace!($TRACE, "{}: {}", $func, format!($fmt, $a)) };
            ( $fmt:expr, $a:expr, $b:expr ) =>
            { trace!($TRACE, "{}: {}", $func, format!($fmt, $a, $b)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr ) =>
            { trace!($TRACE, "{}: {}", $func, format!($fmt, $a, $b, $c)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr ) =>
            { trace!($TRACE, "{}: {}", $func, format!($fmt, $a, $b, $c, $d)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr ) =>
            { trace!($TRACE, "{}: {}", $func, format!($fmt, $a, $b, $c, $d, $e)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr ) =>
            { trace!($TRACE, "{}: {}", $func, format!($fmt, $a, $b, $c, $d, $e, $f)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr ) =>
            { trace!($TRACE, "{}: {}", $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr ) =>
            { trace!($TRACE, "{}: {}", $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr ) =>
            { trace!($TRACE, "{}: {}", $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr ) =>
            { trace!($TRACE, "{}: {}", $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i, $j)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr ) =>
            { trace!($TRACE, "{}: {}", $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k)) };
        }
        struct Indent {}
        impl Indent {
            fn init() -> Self {
                crate::log::INDENT_LEVEL.with(|i| {
                    i.replace_with(|i| *i + 1);
                });
                Indent {}
            }
        }
        impl Drop for Indent {
            fn drop(&mut self) {
                crate::log::INDENT_LEVEL.with(|i| {
                    i.replace_with(|i| *i - 1);
                });
            }
        }
        let _indent = Indent::init();
    }
}
