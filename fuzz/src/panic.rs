// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Utility module containing functions for interacting with the fuzzer allow list

use std::panic::PanicHookInfo;

use backtrace::{Backtrace, BacktraceSymbol};

/// Allow list of panics the fuzzer might trigger which are not indicative of a bug in firecracker
///
/// Panics on this list are specified as tuples of the form
///   (exact panic message, qualified path of function in which the `panic!` macro is)
///
/// If panic message starts with `?` it means that only the beginning of the message will be
/// compared. This is useful when panic message contains run time data.
///
/// If the fuzzer hits a panic on this in "reproduce mode" (e.g. fuzz_stdin feature) it will exit
/// with status code 102 instead of 101 (101 being the default rust panic exit code). Devtool will
/// recognize this and consider the panic "expected". If all crashes originate from expected panics,
/// then devtool will exit with code 0 (and not fail the buildkite pipeline)
///
/// Every panic in this list should be thoroughly documented!
#[allow(unused)] // only used with fuzz_stdin feature
const ALLOW_LIST: [(&'static str, &'static str); 0] = [];

#[allow(unused)] // only used with fuzz_stdin feature
pub fn setup_post_mortem_hook() {
    let std_hook = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |panic_info| {
        let backtrace = Backtrace::new();

        if is_allow_listed_panic(panic_info, &backtrace, &ALLOW_LIST) {
            print_panic(panic_info, &backtrace);
            // A panic normally exits with code 101, we choose 102 to indicate an allowed panic
            std::process::exit(102);
        } else {
            // Delegate to the default hook registered in the standard library for printing the
            // panic.
            std_hook(panic_info);

            // A panic on a device worker thread only unwinds that thread, so the target could
            // otherwise finish normally. Abort instead, as Firecracker does with `panic = "abort"`
            // and as the afl crate's hook does on any thread during fuzzing.
            if std::thread::current().name() != Some("main") {
                std::process::abort();
            }
        }
    }));
}

/// Function that approximates rustc's printing of panics to stderr.
///
/// Needed if we cannot rely on the standard panic hook to do the printing for us, because we need
/// to exit the process in a specific way (e.g. special error code or abort signal)
pub fn print_panic(panic_info: &PanicHookInfo, backtrace: &Backtrace) {
    // Approximate rustc's panic printing
    let message = match panic_info.payload().downcast_ref::<&'static str>() {
        Some(s) => *s,
        None => match panic_info.payload().downcast_ref::<String>() {
            Some(s) => &s[..],
            None => "Box<Any>",
        },
    };
    let location = match panic_info.location() {
        Some(loc) => loc.to_string(),
        None => "(unknown)".to_owned(),
    };

    eprintln!(
        "thread 'main' panicked at '{}', {}\nstack backtrace:\n {:?}",
        message, location, backtrace
    );
}

/// List of all entry points rustc can generate for `panic!` invocations
///
/// There are separate entry points based on whether the `panic!` macro from the `std` or the `core`
/// crate was used, and also based on whether format arguments were provided or not.
#[allow(unused)] // only used with fuzz_stdin feature
const RUSTC_PANIC_ENTRY_POINTS: [&'static str; 4] = [
    // https://github.com/rust-lang/rust/blob/dd12cd6dc631b5e964d541d370ca863c2242376c/library/std/src/panicking.rs#L589-L600
    "std::panicking::begin_panic",
    // https://github.com/rust-lang/rust/blob/69df0f2c2f665d7f4e38a3579a81d4efc0d81034/library/core/src/panicking.rs#L35-L66
    "core::panicking::panic_fmt",
    // https://github.com/rust-lang/rust/blob/c5351ad4dcd9f3d73241b2acbfc6b4631da845c5/library/core/src/panicking.rs#L96-L112
    "core::panicking::panic",
    // https://github.com/rust-lang/rust/blob/c5351ad4dcd9f3d73241b2acbfc6b4631da845c5/library/core/src/panicking.rs#L69-L91
    "core::panicking::panic_str_nounwind",
];

/// Checks if the given BacktraceSymbol is a panic entry point by demangling it and comparing
/// it against [`RUSTC_PANIC_ENTRY_POINTS`]
#[allow(unused)] // only used with fuzz_stdin feature
fn is_panic_entry_point(symbol: &BacktraceSymbol) -> bool {
    if let Some(symbol_name) = symbol.name() {
        // This demangles the name for us
        let name = format!("{:#}", symbol_name);

        if RUSTC_PANIC_ENTRY_POINTS.contains(&name.as_str()) {
            return true;
        }
    }

    false
}

/// Matches the given panic against the allow list, returning [`true`] if it is on the allow list,
/// and [`false`] otherwise
#[allow(unused)] // only used with fuzz_stdin feature
fn is_allow_listed_panic(
    panic_info: &PanicHookInfo,
    backtrace: &Backtrace,
    allow_list: &[(&str, &str)],
) -> bool {
    // Try to extract the panic message from the given [`PanicInfo`] object.
    //
    // Matches the standard library implementation for printing panic messages, see
    // https://github.com/rust-lang/rust/blob/4b9f4b221b92193c7e95b1beb502c6eb32c3b613/library/std/src/panicking.rs#L194-L200
    // Cannot be extracted into function for lifetime reasons
    let message = match panic_info.payload().downcast_ref::<&'static str>() {
        Some(s) => *s,
        None => match panic_info.payload().downcast_ref::<String>() {
            Some(s) => &s[..],
            // we use the message to check if the panic is on the allow list. If there's no message,
            // then we can't perform this check. Mark panic as unexpected.
            None => return false,
        },
    };
    // `PanicInfo::location` always returns `Some`, see
    // https://doc.rust-lang.org/std/panic/struct.PanicInfo.html#method.location
    // If that ever changes, all panics without location will be reported as unexpected
    let file = match panic_info.location() {
        Some(location) => location.file(),
        None => return false,
    };

    // Look for the stack frame `std::panicking::begin_panic` or `core::panicking::panic_fmt`. The
    // frame after this will be the one in which the panic originated
    let mut found_panic_entry_point = false;
    let mut origin = None;

    // Get the backtrace symbol _following_ the std::panicking::begin_panic symbol
    // The backtrace starts at the call to `Backtrace::new()` and then walks up to call-stack.
    'frame_iter: for frame in backtrace.frames() {
        // There can be multiple symbols if inlining happened (in which case the first symbol is the
        // "innermost" function).
        // Most panic entry points (those that are called by the panic! macro) are not inlined,
        // however some others could theoretically get inlined. In case of inlining, a single frame
        // contains multiple symbols, with the first symbol being the outer-most function, and the
        // last symbol the most-inlined function. This means we have to iterate over the symbols in
        // reverse to walk up the call stack.
        for symbol in frame.symbols().iter().rev() {
            // some panic entry-points delegate to each other, so we need to find the last entry
            // point in a consecutive list of panic entry-points
            if is_panic_entry_point(symbol) {
                found_panic_entry_point = true;
            } else if found_panic_entry_point {
                // We are not a panic entry point ourselves, we have found a panic entry point in
                // the previous iteration. This must be the function that invoked `panic!`.
                origin = Some(symbol);
                break 'frame_iter;
            }
        }
    }

    let origin = match origin {
        Some(origin) => origin,
        None => return false, // failed to resolve panic origin, report as unexpected
    };
    let origin_name = match origin.name() {
        Some(symbol_name) => format!("{:#}", symbol_name),
        None => return false,
    };

    // sanity check: does the backtrace frame's file match the panic's info file?
    // note that the backtrace only has file information if debug symbols are present (by default
    // not the case when using `cargo afl run`)
    if let Some(path) = origin.filename() {
        // `end_with` as `BacktraceFrame::filename` includes the pwd
        if !path.ends_with(file) {
            // We somehow managed to resolve a backtrace frame whose file does not match what the
            // panic info object told us. This happens for example if the panic is due to an
            // `unwrap`. Marking as unexpected.
            return false;
        }
    }

    for entry in allow_list {
        let error_msg = match entry.0.strip_prefix('?') {
            Some(e) => e,
            None => entry.0,
        };
        let error_orig = entry.1;
        if message.starts_with(error_msg) && origin_name == error_orig {
            return true;
        }
    }

    false
}
