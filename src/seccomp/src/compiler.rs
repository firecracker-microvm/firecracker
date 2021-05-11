// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Module responsible for compiling the deserialized filter objects into BPF code.
//! Used by the seccompiler binary.
//!
//! It also defines most of the objects that a seccomp filter is deserialized into:
//! [`Filter`](struct.Filter.html),
//! [`SyscallRule`](struct.SyscallRule.html).
//!
//! The rest of objects are deserialized directly into the IR (intermediate representation):
//! [`SeccompCondition`](../../seccomp/struct.SeccompCondition.html),
//! [`SeccompAction`](../../seccomp/enum.SeccompAction.html),
//! [`SeccompCmpOp`](../../seccomp/enum.SeccompCmpOp.html),
//! [`SeccompCmpArgLen`](../../seccomp/enum.SeccompCmpArgLen.html).
//!
//! ```text
//! The compilation goes through a couple of steps, from JSON to BPF:
//!
//!                  JSON
//!                   |
//!            (via serde_json)
//!                   |
//!                   V
//!       collection of `Filter` objects
//!                   |
//!      (via Compiler.compile_blob(...))
//!                   |
//!                   V
//!   collection of `SeccompFilter` objects
//!     (IR - intermediate representation)
//!                   |
//!    (via SeccompFilter.try_into::<BpfProgram>(...))
//!                   |
//!                   V
//!     collection of `BpfProgram` objects
//! ```

use super::syscall_table::SyscallTable;
use seccomp::{
    BpfThreadMap, Comment, Error as SeccompFilterError, SeccompAction, SeccompCondition,
    SeccompFilter, SeccompRule, SeccompRuleMap, TargetArch,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::{Into, TryInto};
use std::fmt;

/// Errors compiling Filters into BPF.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Error from the SeccompFilter.
    SeccompFilter(SeccompFilterError),
    /// Invalid syscall name for the given arch.
    SyscallName(String, TargetArch),
}

type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            SeccompFilter(ref err) => write!(f, "{}", err),
            SyscallName(ref syscall_name, ref arch) => write!(
                f,
                "Invalid syscall name: {} for given arch: {:?}.",
                syscall_name, arch
            ),
        }
    }
}

/// Deserializable object representing a syscall rule.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SyscallRule {
    /// Name of the syscall.
    syscall: String,
    /// Optional on-match action.
    action: Option<SeccompAction>,
    /// Rule conditions.
    #[serde(rename = "args")]
    conditions: Option<Vec<SeccompCondition>>,
    /// Optional empty value, represents a `comment` property in the JSON file.
    comment: Option<Comment>,
}

impl SyscallRule {
    /// Perform semantic checks after deserialization.
    fn validate(&self) -> Result<()> {
        // Validate all `SeccompCondition`s.
        if let Some(conditions) = self.conditions.as_ref() {
            return conditions
                .iter()
                .filter_map(|cond| cond.validate().err())
                .next()
                .map_or(Ok(()), |err| Err(Error::SeccompFilter(err)));
        }

        Ok(())
    }
}

/// Deserializable seccomp filter. Refers to one thread category.
#[derive(Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Filter {
    /// Default action if no rules match. e.g. `Kill` for an AllowList.
    default_action: SeccompAction,
    /// Default action if a rule matches. e.g. `Allow` for an AllowList.
    filter_action: SeccompAction,
    /// The collection of `SyscallRule`s.
    filter: Vec<SyscallRule>,
}

impl Filter {
    /// Perform semantic checks after deserialization.
    fn validate(&self) -> Result<()> {
        // Validate all `SyscallRule`s.
        self.filter
            .iter()
            .filter_map(|syscall_rule| syscall_rule.validate().err())
            .next()
            .map_or(Ok(()), Err)
    }
}

/// Object responsible for compiling `Filter`s into `BpfProgram`s.
/// Uses the `SeccompFilter` defined in `src/lib.rs` interface as an IR language.
pub(crate) struct Compiler {
    /// Target architecture. Can be different from the current `target_arch`.
    arch: TargetArch,
    /// Target-specific syscall table.
    syscall_table: SyscallTable,
}

impl Compiler {
    pub fn new(arch: TargetArch) -> Self {
        Self {
            arch,
            syscall_table: SyscallTable::new(arch),
        }
    }

    /// Perform semantic checks after deserialization.
    fn validate_filters(&self, filters: &HashMap<String, Filter>) -> Result<()> {
        // Validate all `Filter`s.
        filters
            .iter()
            .filter_map(|(_, filter)| filter.validate().err())
            .next()
            .map_or(Ok(()), Err)
    }

    /// Main compilation function.
    pub fn compile_blob(&self, filters: HashMap<String, Filter>) -> Result<BpfThreadMap> {
        self.validate_filters(&filters)?;
        let mut bpf_map = BpfThreadMap::new();

        for (thread_name, filter) in filters.into_iter() {
            bpf_map.insert(
                thread_name,
                self.make_seccomp_filter(filter)?
                    .try_into()
                    .map_err(Error::SeccompFilter)?,
            );
        }
        Ok(bpf_map)
    }

    /// Transforms the deserialized `Filter` into a `SeccompFilter` (IR language).
    fn make_seccomp_filter(&self, filter: Filter) -> Result<SeccompFilter> {
        let mut rule_map: SeccompRuleMap = SeccompRuleMap::new();
        let filter_action = &filter.filter_action;

        for syscall_rule in filter.filter {
            let syscall_name = syscall_rule.syscall;
            let action = match syscall_rule.action {
                Some(action) => action,
                None => filter_action.clone(),
            };
            let syscall_nr = self
                .syscall_table
                .get_syscall_nr(&syscall_name)
                .ok_or_else(|| Error::SyscallName(syscall_name.clone(), self.arch))?;
            let rule_accumulator = rule_map.entry(syscall_nr).or_insert_with(Vec::new);

            match syscall_rule.conditions {
                Some(conditions) => rule_accumulator.push(SeccompRule::new(conditions, action)),
                None => rule_accumulator.push(SeccompRule::new(vec![], action)),
            };
        }

        SeccompFilter::new(rule_map, filter.default_action, self.arch.into())
            .map_err(Error::SeccompFilter)
    }
}

#[cfg(test)]
mod tests {
    use super::{Compiler, Error, Filter, SyscallRule};
    use seccomp::{
        Error as SeccompFilterError, SeccompAction, SeccompCmpArgLen::*, SeccompCmpOp::*,
        SeccompCondition as Cond, SeccompFilter, SeccompRule, SyscallRuleSet, TargetArch,
    };
    use std::collections::HashMap;
    use std::convert::TryInto;
    use std::env::consts::ARCH;

    impl Filter {
        pub fn new(
            default_action: SeccompAction,
            filter_action: SeccompAction,
            filter: Vec<SyscallRule>,
        ) -> Filter {
            Filter {
                default_action,
                filter_action,
                filter,
            }
        }
    }

    impl SyscallRule {
        pub fn new(
            syscall: String,
            action: Option<SeccompAction>,
            conditions: Option<Vec<Cond>>,
        ) -> SyscallRule {
            SyscallRule {
                syscall,
                action,
                conditions,
                comment: None,
            }
        }
    }

    fn match_syscall(syscall_number: i64, action: SeccompAction) -> SyscallRuleSet {
        (syscall_number, vec![SeccompRule::new(vec![], action)])
    }

    fn match_syscall_if(syscall_number: i64, rules: Vec<SeccompRule>) -> SyscallRuleSet {
        (syscall_number, rules)
    }

    #[test]
    // Test the transformation of Filter objects into SeccompFilter objects.
    // We test this private method because we are interested in seeing that the
    // Filter -> SeccompFilter transformation is done correctly.
    fn test_make_seccomp_filter() {
        let compiler = Compiler::new(ARCH.try_into().unwrap());
        // Test a well-formed filter. Malformed filters are tested in test_compile_blob().
        let filter = Filter::new(
            SeccompAction::Trap,
            SeccompAction::Allow,
            vec![
                SyscallRule::new("read".to_string(), Some(SeccompAction::Log), None),
                SyscallRule::new(
                    "futex".to_string(),
                    Some(SeccompAction::Log),
                    Some(vec![
                        Cond::new(2, DWORD, Le, 65).unwrap(),
                        Cond::new(1, QWORD, Ne, 80).unwrap(),
                    ]),
                ),
                SyscallRule::new(
                    "futex".to_string(),
                    None,
                    Some(vec![
                        Cond::new(3, QWORD, Gt, 65).unwrap(),
                        Cond::new(1, QWORD, Lt, 80).unwrap(),
                    ]),
                ),
                SyscallRule::new(
                    "futex".to_string(),
                    None,
                    Some(vec![Cond::new(3, QWORD, Ge, 65).unwrap()]),
                ),
                SyscallRule::new(
                    "ioctl".to_string(),
                    None,
                    Some(vec![Cond::new(3, DWORD, MaskedEq(100), 65).unwrap()]),
                ),
            ],
        );

        // The expected IR.
        let seccomp_filter = SeccompFilter::new(
            vec![
                match_syscall(
                    compiler.syscall_table.get_syscall_nr("read").unwrap(),
                    SeccompAction::Log,
                ),
                match_syscall_if(
                    compiler.syscall_table.get_syscall_nr("futex").unwrap(),
                    vec![
                        SeccompRule::new(
                            vec![
                                Cond::new(2, DWORD, Le, 65).unwrap(),
                                Cond::new(1, QWORD, Ne, 80).unwrap(),
                            ],
                            SeccompAction::Log,
                        ),
                        SeccompRule::new(
                            vec![
                                Cond::new(3, QWORD, Gt, 65).unwrap(),
                                Cond::new(1, QWORD, Lt, 80).unwrap(),
                            ],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![Cond::new(3, QWORD, Ge, 65).unwrap()],
                            SeccompAction::Allow,
                        ),
                    ],
                ),
                match_syscall_if(
                    compiler.syscall_table.get_syscall_nr("ioctl").unwrap(),
                    vec![SeccompRule::new(
                        vec![Cond::new(3, DWORD, MaskedEq(100), 65).unwrap()],
                        SeccompAction::Allow,
                    )],
                ),
            ]
            .into_iter()
            .collect(),
            SeccompAction::Trap,
            ARCH,
        )
        .unwrap();

        assert_eq!(
            compiler.make_seccomp_filter(filter).unwrap(),
            seccomp_filter
        );
    }

    #[test]
    fn test_compile_blob() {
        let compiler = Compiler::new(ARCH.try_into().unwrap());
        // Test with malformed filters.

        let mut wrong_syscall_name_filters = HashMap::new();
        wrong_syscall_name_filters.insert(
            "T1".to_string(),
            Filter::new(
                SeccompAction::Trap,
                SeccompAction::Allow,
                vec![SyscallRule::new("wrong_syscall".to_string(), None, None)],
            ),
        );

        assert_eq!(
            compiler.compile_blob(wrong_syscall_name_filters),
            Err(Error::SyscallName(
                "wrong_syscall".to_string(),
                compiler.arch
            ))
        );

        // Test with correct filters.
        let mut correct_filters = HashMap::new();
        correct_filters.insert(
            "Thread1".to_string(),
            Filter::new(
                SeccompAction::Trap,
                SeccompAction::Allow,
                vec![
                    SyscallRule::new("read".to_string(), None, None),
                    SyscallRule::new(
                        "futex".to_string(),
                        None,
                        Some(vec![
                            Cond::new(1, DWORD, Eq, 65).unwrap(),
                            Cond::new(2, QWORD, Le, 80).unwrap(),
                        ]),
                    ),
                    SyscallRule::new(
                        "futex".to_string(),
                        None,
                        Some(vec![
                            Cond::new(3, DWORD, Eq, 65).unwrap(),
                            Cond::new(2, QWORD, Le, 80).unwrap(),
                        ]),
                    ),
                ],
            ),
        );

        // We don't test the BPF compilation in this module.
        // This is done in the seccomp/lib.rs module.
        // Here, we only test the (Filter -> SeccompFilter) transformations. (High-level -> IR)
        assert!(compiler.compile_blob(correct_filters).is_ok());
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(
            format!(
                "{}",
                Error::SeccompFilter(SeccompFilterError::InvalidArgumentNumber)
            ),
            "The seccomp rule contains an invalid argument number."
        );
        assert_eq!(
            format!(
                "{}",
                Error::SyscallName("asdsad".to_string(), TargetArch::x86_64)
            ),
            format!(
                "Invalid syscall name: {} for given arch: {}.",
                "asdsad", "x86_64"
            )
        );
    }
}
