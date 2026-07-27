// SPDX-License-Identifier: GPL-2.0-only
//! Always-on kernel invariant checks.

use core::fmt;

use crate::kernel::panic::{self, PanicLocation};

#[cold]
#[inline(never)]
pub(crate) fn bug_failed(expr: &'static str, location: PanicLocation<'static>) -> ! {
    panic::assertion_failed(expr, None, location)
}

#[cold]
#[inline(never)]
pub(crate) fn bug_failed_msg(
    expr: &'static str,
    msg: fmt::Arguments<'_>,
    location: PanicLocation<'static>,
) -> ! {
    panic::assertion_failed(expr, Some(msg), location)
}

#[cold]
#[inline(never)]
pub(crate) fn bug_now(msg: fmt::Arguments<'_>, location: PanicLocation<'static>) -> ! {
    panic::bug("bug", None, Some(msg), location)
}

#[cold]
#[inline(never)]
pub(crate) fn bug_on_failed(
    expr: &'static str,
    msg: Option<fmt::Arguments<'_>>,
    location: PanicLocation<'static>,
) -> ! {
    panic::bug("bug_on", Some(expr), msg, location)
}

#[cold]
#[inline(never)]
pub(crate) fn bug_eq_failed(
    expr: &'static str,
    msg: Option<fmt::Arguments<'_>>,
    location: PanicLocation<'static>,
) -> ! {
    panic::assertion_eq_failed(expr, msg, location)
}

#[cold]
#[inline(never)]
pub(crate) fn bug_ne_failed(
    expr: &'static str,
    msg: Option<fmt::Arguments<'_>>,
    location: PanicLocation<'static>,
) -> ! {
    panic::assertion_ne_failed(expr, msg, location)
}

#[allow(unused_macros)]
macro_rules! kassert {
    ($cond:expr $(,)?) => {{
        if !$cond {
            $crate::kernel::bug::bug_failed(
                stringify!($cond),
                $crate::kernel::panic::PanicLocation::new(file!(), line!(), column!()),
            );
        }
    }};
    ($cond:expr, $($arg:tt)+) => {{
        if !$cond {
            $crate::kernel::bug::bug_failed_msg(
                stringify!($cond),
                format_args!($($arg)+),
                $crate::kernel::panic::PanicLocation::new(file!(), line!(), column!()),
            );
        }
    }};
}

#[allow(unused_macros)]
macro_rules! kassert_eq {
    ($left:expr, $right:expr $(,)?) => {{
        let left = &$left;
        let right = &$right;
        if !(left == right) {
            $crate::kernel::bug::bug_eq_failed(
                concat!(stringify!($left), " == ", stringify!($right)),
                None,
                $crate::kernel::panic::PanicLocation::new(file!(), line!(), column!()),
            );
        }
    }};
    ($left:expr, $right:expr, $($arg:tt)+) => {{
        let left = &$left;
        let right = &$right;
        if !(left == right) {
            $crate::kernel::bug::bug_eq_failed(
                concat!(stringify!($left), " == ", stringify!($right)),
                Some(format_args!($($arg)+)),
                $crate::kernel::panic::PanicLocation::new(file!(), line!(), column!()),
            );
        }
    }};
}

#[allow(unused_macros)]
macro_rules! kassert_ne {
    ($left:expr, $right:expr $(,)?) => {{
        let left = &$left;
        let right = &$right;
        if !(left != right) {
            $crate::kernel::bug::bug_ne_failed(
                concat!(stringify!($left), " != ", stringify!($right)),
                None,
                $crate::kernel::panic::PanicLocation::new(file!(), line!(), column!()),
            );
        }
    }};
    ($left:expr, $right:expr, $($arg:tt)+) => {{
        let left = &$left;
        let right = &$right;
        if !(left != right) {
            $crate::kernel::bug::bug_ne_failed(
                concat!(stringify!($left), " != ", stringify!($right)),
                Some(format_args!($($arg)+)),
                $crate::kernel::panic::PanicLocation::new(file!(), line!(), column!()),
            );
        }
    }};
}

#[allow(unused_macros)]
macro_rules! kbug {
    ($($arg:tt)+) => {{
        $crate::kernel::bug::bug_now(
            format_args!($($arg)+),
            $crate::kernel::panic::PanicLocation::new(file!(), line!(), column!()),
        );
    }};
}

#[allow(unused_macros)]
macro_rules! kbug_on {
    ($cond:expr $(,)?) => {{
        if $cond {
            $crate::kernel::bug::bug_on_failed(
                concat!("BUG_ON(", stringify!($cond), ")"),
                None,
                $crate::kernel::panic::PanicLocation::new(file!(), line!(), column!()),
            );
        }
    }};
    ($cond:expr, $($arg:tt)+) => {{
        if $cond {
            $crate::kernel::bug::bug_on_failed(
                concat!("BUG_ON(", stringify!($cond), ")"),
                Some(format_args!($($arg)+)),
                $crate::kernel::panic::PanicLocation::new(file!(), line!(), column!()),
            );
        }
    }};
}

pub(crate) use kassert;
pub(crate) use kassert_eq;
#[allow(unused_imports)]
pub(crate) use kassert_ne;
#[allow(unused_imports)]
pub(crate) use kbug;
#[allow(unused_imports)]
pub(crate) use kbug_on;
