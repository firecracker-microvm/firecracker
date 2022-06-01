// Copyright 2022 Ametros. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::builder::StartMicrovmError;
use std::result::Result;

// The "unchecked" refers to from_utf8_unchecked(), i.e. bs must be valid UTF-8
fn trimmed_str_unchecked(bs: &[u8]) -> &str {
    std::str::from_utf8(bs).unwrap().trim()
}

// Returns true iff bs is b"--" or starts b"--<space>"
fn is_delim(bs: &[u8]) -> bool {
    bs == b"--" || (bs.len() > 2 && bs[0] == b'-' && bs[1] == b'-' && bs[2].is_ascii_whitespace())
}

// Returns the index of the first ASCII whitespace character in bs
fn next_space(bs: &[u8]) -> Option<usize> {
    let mut ret = 0usize;
    loop {
        if ret >= bs.len() {
            break None;
        }
        if bs[ret].is_ascii_whitespace() {
            break Some(ret);
        }

        ret += 1
    }
}

// Splits cmdline on a space-delimited "--". This is complicated by the need to return
// references into the argument, so can't e.g. split on whitespace and accumulate.
//
// Bugs wrt the kernel's command line parser:
//  - Kernel defines 160 as whitespace, but cmdline is UTF-8, so for now just disallow it.
//  - Kernel also defines vertical tab (11) as whitespace but it's simpler to disallow that too.
//  - Kernel permits double-quoted parameter values, e.g foo.bar="blah -- blah"; if those values
//    contain "--" then we'll erroneously split on that "--".
pub fn split(cmdline: &str) -> Result<(&str, &str), StartMicrovmError> {
    let bs = cmdline.as_bytes();

    // Exclude:
    //  - non-ASCII cmdline
    //  - cmdline is empty
    //  - cmdline starts with --, i.e. is "--" or "--<space>"
    if !cmdline.is_ascii() {
        Err(StartMicrovmError::KernelCmdline(
            "Kernel cmdline is not ASCII".to_string(),
        ))
    } else if cmdline.is_empty() || cmdline == "--" {
        Ok(("", ""))
    } else if is_delim(bs) {
        Ok(("", trimmed_str_unchecked(&bs[3..])))
    } else {
        // Look for the delimiter
        let mut it = bs;
        Ok(loop {
            match next_space(it) {
                None => break (cmdline, ""),
                Some(x) if is_delim(&it[x + 1..]) => {
                    // Safety: bs is 7-bit ASCII
                    break (
                        trimmed_str_unchecked(&bs[..bs.len() - it.len() + x]),
                        trimmed_str_unchecked(&it[x + 3..]),
                    );
                }
                Some(x) => it = &it[x + 1..],
            }
        })
    }
}

#[cfg(test)]
pub mod tests {
    #[test]
    fn test_split() {
        struct TestCase {
            cmdline: &'static str,
            kernel: &'static str,
            init: &'static str,
        }

        let test_cases = &[
            TestCase {
                cmdline: "",
                kernel: "",
                init: "",
            },
            TestCase {
                cmdline: "--",
                kernel: "",
                init: "",
            },
            TestCase {
                cmdline: " --",
                kernel: "",
                init: "",
            },
            TestCase {
                cmdline: "-- ",
                kernel: "",
                init: "",
            },
            TestCase {
                cmdline: "foo",
                kernel: "foo",
                init: "",
            },
            TestCase {
                cmdline: "--foo",
                kernel: "--foo",
                init: "",
            },
            TestCase {
                cmdline: "foo--",
                kernel: "foo--",
                init: "",
            },
            TestCase {
                cmdline: "foo --",
                kernel: "foo",
                init: "",
            },
            TestCase {
                cmdline: "-- foo",
                kernel: "",
                init: "foo",
            },
            TestCase {
                cmdline: " -- ",
                kernel: "",
                init: "",
            },
            TestCase {
                cmdline: "foo -- bar",
                kernel: "foo",
                init: "bar",
            },
            TestCase {
                cmdline: "--foo -- bar",
                kernel: "--foo",
                init: "bar",
            },
            TestCase {
                cmdline: "foo --bar -- qux",
                kernel: "foo --bar",
                init: "qux",
            },
            TestCase {
                cmdline: "foo -- bar -- qux",
                kernel: "foo",
                init: "bar -- qux",
            },
        ];

        for it in test_cases.iter() {
            let (kernel, init) = super::split(it.cmdline).unwrap();
            assert_eq!(kernel, it.kernel);
            assert_eq!(init, it.init);
        }
    }
}
