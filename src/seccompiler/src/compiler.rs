// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Module defining the logic for compiling the deserialized filter objects into the IR.
//! Used by seccompiler-bin.
//!
//! Via the `Compiler::compile_blob()` method, it also drives the entire JSON -> BLOB
//! transformation process.
//!
//! It also defines some of the objects that a JSON seccomp filter is deserialized into:
//! [`Filter`](struct.Filter.html),
//! [`SyscallRule`](struct.SyscallRule.html).
//
//! The rest of objects are deserialized directly into the IR (intermediate representation):
//! [`SeccompCondition`](../backend/struct.SeccompCondition.html),
//! [`SeccompAction`](../backend/enum.SeccompAction.html),
//! [`SeccompCmpOp`](../backend/enum.SeccompCmpOp.html),
//! [`SeccompCmpArgLen`](../backend/enum.SeccompCmpArgLen.html).

use std::collections::BTreeMap;
use std::convert::{Into, TryInto};
use std::{fmt, result};

use serde::de::{self, Error as _, MapAccess, Visitor};
use serde::Deserialize;

use crate::backend::{
    Comment, FilterError, SeccompAction, SeccompCondition, SeccompFilter, SeccompRule,
    SeccompRuleMap, TargetArch,
};
use crate::common::BpfProgram;
use crate::syscall_table::SyscallTable;

/// Errors compiling Filters into BPF.
#[derive(Debug, PartialEq, thiserror::Error, displaydoc::Display)]
pub enum CompilationError {
    /// `filter_action` and `default_action` are equal.
    IdenticalActions,
    /// {0}
    Filter(#[from] FilterError),
    /// Invalid syscall name: {0} for given arch: {1:?}.
    SyscallName(String, TargetArch),
}

/// Deserializable object that represents the Json filter file.
#[derive(Debug)]
pub struct JsonFile(pub BTreeMap<String, Filter>);

// Implement a custom deserializer, that returns an error for duplicate thread keys.
impl<'de> Deserialize<'de> for JsonFile {
    fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        #[derive(Debug)]
        struct JsonFileVisitor;

        impl<'d> Visitor<'d> for JsonFileVisitor {
            type Value = BTreeMap<String, Filter>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> result::Result<(), fmt::Error> {
                f.write_str("a map of filters")
            }

            fn visit_map<M>(self, mut access: M) -> result::Result<Self::Value, M::Error>
            where
                M: MapAccess<'d>,
            {
                let mut values = Self::Value::new();

                while let Some((key, value)) = access.next_entry()? {
                    if values.insert(key, value).is_some() {
                        return Err(M::Error::custom("duplicate filter key"));
                    };
                }

                Ok(values)
            }
        }
        Ok(JsonFile(deserializer.deserialize_map(JsonFileVisitor)?))
    }
}

/// Deserializable object representing a syscall rule.
#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct SyscallRule {
    /// Name of the syscall.
    syscall: String,
    /// Rule conditions.
    #[serde(rename = "args")]
    conditions: Option<Vec<SeccompCondition>>,
    /// Optional empty value, represents a `comment` property in the JSON file.
    comment: Option<Comment>,
}

impl SyscallRule {
    /// Perform semantic checks after deserialization.
    fn validate(&self) -> Result<(), CompilationError> {
        // Validate all `SeccompCondition`s.
        if let Some(conditions) = self.conditions.as_ref() {
            return conditions
                .iter()
                .filter_map(|cond| cond.validate().err())
                .next()
                .map_or(Ok(()), |err| Err(CompilationError::Filter(err)));
        }

        Ok(())
    }
}

/// Deserializable seccomp filter. Refers to one thread category.
#[derive(Deserialize, PartialEq, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    /// Default action if no rules match. e.g. `Kill` for an AllowList.
    default_action: SeccompAction,
    /// Default action if a rule matches. e.g. `Allow` for an AllowList.
    filter_action: SeccompAction,
    /// The collection of `SyscallRule`s.
    filter: Vec<SyscallRule>,
}

impl Filter {
    /// Perform semantic checks after deserialization.
    fn validate(&self) -> Result<(), CompilationError> {
        // Doesn't make sense to have equal default and on-match actions.
        if self.default_action == self.filter_action {
            return Err(CompilationError::IdenticalActions);
        }

        // Validate all `SyscallRule`s.
        self.filter
            .iter()
            .filter_map(|syscall_rule| syscall_rule.validate().err())
            .next()
            .map_or(Ok(()), Err)
    }
}

/// Object responsible for compiling [`Filter`](struct.Filter.html)s into
/// [`BpfProgram`](../common/type.BpfProgram.html)s.
/// Uses the [`SeccompFilter`](../backend/struct.SeccompFilter.html) interface as an IR language.
#[derive(Debug)]
pub struct Compiler {
    /// Target architecture. Can be different from the current `target_arch`.
    arch: TargetArch,
    /// Target-specific syscall table.
    syscall_table: SyscallTable,
}

impl Compiler {
    /// Create a new `Compiler` instance, for the given target architecture.
    pub fn new(arch: TargetArch) -> Self {
        Self {
            arch,
            syscall_table: SyscallTable::new(arch),
        }
    }

    /// Perform semantic checks after deserialization.
    fn validate_filters(&self, filters: &BTreeMap<String, Filter>) -> Result<(), CompilationError> {
        // Validate all `Filter`s.
        filters
            .iter()
            .filter_map(|(_, filter)| filter.validate().err())
            .next()
            .map_or(Ok(()), Err)
    }

    /// Main compilation function.
    pub fn compile_blob(
        &self,
        filters: BTreeMap<String, Filter>,
        is_basic: bool,
    ) -> Result<BTreeMap<String, BpfProgram>, CompilationError> {
        self.validate_filters(&filters)?;
        let mut bpf_map: BTreeMap<String, BpfProgram> = BTreeMap::new();

        for (thread_name, filter) in filters.into_iter() {
            if is_basic {
                bpf_map.insert(
                    thread_name,
                    self.make_basic_seccomp_filter(filter)?.try_into()?,
                );
            } else {
                bpf_map.insert(thread_name, self.make_seccomp_filter(filter)?.try_into()?);
            }
        }
        Ok(bpf_map)
    }

    /// Transforms the deserialized `Filter` into a `SeccompFilter` (IR language).
    fn make_seccomp_filter(&self, filter: Filter) -> Result<SeccompFilter, CompilationError> {
        let mut rule_map: SeccompRuleMap = SeccompRuleMap::new();
        let filter_action = &filter.filter_action;

        for syscall_rule in filter.filter {
            let syscall_name = syscall_rule.syscall;
            let action = filter_action.clone();
            let syscall_nr = self
                .syscall_table
                .get_syscall_nr(&syscall_name)
                .ok_or_else(|| CompilationError::SyscallName(syscall_name.clone(), self.arch))?;
            let rule_accumulator = rule_map.entry(syscall_nr).or_insert_with(Vec::new);

            match syscall_rule.conditions {
                Some(conditions) => rule_accumulator.push(SeccompRule::new(conditions, action)),
                None => rule_accumulator.push(SeccompRule::new(vec![], action)),
            };
        }

        SeccompFilter::new(rule_map, filter.default_action, self.arch.into())
            .map_err(CompilationError::Filter)
    }

    /// Transforms the deserialized `Filter` into a basic `SeccompFilter` (IR language).
    /// This filter will drop any argument checks and any rule-level action.
    /// All rules will trigger the filter-level `filter_action`.
    fn make_basic_seccomp_filter(&self, filter: Filter) -> Result<SeccompFilter, CompilationError> {
        let mut rule_map: SeccompRuleMap = SeccompRuleMap::new();
        let filter_action = &filter.filter_action;

        for syscall_rule in filter.filter {
            let syscall_name = syscall_rule.syscall;
            // Basic filters bypass the rule-level action and use the filter_action.
            let action = filter_action.clone();
            let syscall_nr = self
                .syscall_table
                .get_syscall_nr(&syscall_name)
                .ok_or_else(|| CompilationError::SyscallName(syscall_name.clone(), self.arch))?;

            // If there is already an entry for this syscall, do nothing.
            // Otherwise, insert an empty rule that triggers the filter_action.
            rule_map
                .entry(syscall_nr)
                .or_insert_with(|| vec![SeccompRule::new(vec![], action)]);
        }

        SeccompFilter::new(rule_map, filter.default_action, self.arch.into())
            .map_err(CompilationError::Filter)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::TryInto;
    use std::env::consts::ARCH;

    use super::{CompilationError, Compiler, Filter, SyscallRule};
    use crate::backend::SeccompCmpArgLen::*;
    use crate::backend::SeccompCmpOp::*;
    use crate::backend::{
        FilterError, SeccompAction, SeccompCondition as Cond, SeccompFilter, SeccompRule,
        TargetArch,
    };

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
        pub fn new(syscall: String, conditions: Option<Vec<Cond>>) -> SyscallRule {
            SyscallRule {
                syscall,
                conditions,
                comment: None,
            }
        }
    }

    fn match_syscall(syscall_number: i64, action: SeccompAction) -> (i64, Vec<SeccompRule>) {
        (syscall_number, vec![SeccompRule::new(vec![], action)])
    }

    fn match_syscall_if(syscall_number: i64, rules: Vec<SeccompRule>) -> (i64, Vec<SeccompRule>) {
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
                SyscallRule::new("read".to_string(), None),
                SyscallRule::new(
                    "futex".to_string(),
                    Some(vec![
                        Cond::new(2, Dword, Le, 65).unwrap(),
                        Cond::new(1, Qword, Ne, 80).unwrap(),
                    ]),
                ),
                SyscallRule::new(
                    "futex".to_string(),
                    Some(vec![
                        Cond::new(3, Qword, Gt, 65).unwrap(),
                        Cond::new(1, Qword, Lt, 80).unwrap(),
                    ]),
                ),
                SyscallRule::new(
                    "futex".to_string(),
                    Some(vec![Cond::new(3, Qword, Ge, 65).unwrap()]),
                ),
                SyscallRule::new(
                    "ioctl".to_string(),
                    Some(vec![Cond::new(3, Dword, MaskedEq(100), 65).unwrap()]),
                ),
            ],
        );

        // The expected IR.
        let seccomp_filter = SeccompFilter::new(
            vec![
                match_syscall(
                    compiler.syscall_table.get_syscall_nr("read").unwrap(),
                    SeccompAction::Allow,
                ),
                match_syscall_if(
                    compiler.syscall_table.get_syscall_nr("futex").unwrap(),
                    vec![
                        SeccompRule::new(
                            vec![
                                Cond::new(2, Dword, Le, 65).unwrap(),
                                Cond::new(1, Qword, Ne, 80).unwrap(),
                            ],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![
                                Cond::new(3, Qword, Gt, 65).unwrap(),
                                Cond::new(1, Qword, Lt, 80).unwrap(),
                            ],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![Cond::new(3, Qword, Ge, 65).unwrap()],
                            SeccompAction::Allow,
                        ),
                    ],
                ),
                match_syscall_if(
                    compiler.syscall_table.get_syscall_nr("ioctl").unwrap(),
                    vec![SeccompRule::new(
                        vec![Cond::new(3, Dword, MaskedEq(100), 65).unwrap()],
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
    // Test the transformation of Filter objects into SeccompFilter objects.
    // This `basic` alternative version of the make_seccomp_filter method drops argument checks.
    fn test_make_basic_seccomp_filter() {
        let compiler = Compiler::new(ARCH.try_into().unwrap());
        // Test a well-formed filter. Malformed filters are tested in test_compile_blob().
        let filter = Filter::new(
            SeccompAction::Trap,
            SeccompAction::Allow,
            vec![
                SyscallRule::new("read".to_string(), None),
                SyscallRule::new(
                    "futex".to_string(),
                    Some(vec![
                        Cond::new(2, Dword, Le, 65).unwrap(),
                        Cond::new(1, Qword, Ne, 80).unwrap(),
                    ]),
                ),
                SyscallRule::new(
                    "futex".to_string(),
                    Some(vec![
                        Cond::new(3, Qword, Gt, 65).unwrap(),
                        Cond::new(1, Qword, Lt, 80).unwrap(),
                    ]),
                ),
                SyscallRule::new(
                    "futex".to_string(),
                    Some(vec![Cond::new(3, Qword, Ge, 65).unwrap()]),
                ),
                SyscallRule::new(
                    "ioctl".to_string(),
                    Some(vec![Cond::new(3, Dword, MaskedEq(100), 65).unwrap()]),
                ),
            ],
        );

        // The expected IR.
        let seccomp_filter = SeccompFilter::new(
            vec![
                match_syscall(
                    compiler.syscall_table.get_syscall_nr("read").unwrap(),
                    SeccompAction::Allow,
                ),
                match_syscall(
                    compiler.syscall_table.get_syscall_nr("futex").unwrap(),
                    SeccompAction::Allow,
                ),
                match_syscall(
                    compiler.syscall_table.get_syscall_nr("ioctl").unwrap(),
                    SeccompAction::Allow,
                ),
            ]
            .into_iter()
            .collect(),
            SeccompAction::Trap,
            ARCH,
        )
        .unwrap();

        assert_eq!(
            compiler.make_basic_seccomp_filter(filter).unwrap(),
            seccomp_filter
        );
    }

    #[test]
    fn test_compile_blob() {
        let compiler = Compiler::new(ARCH.try_into().unwrap());
        // Test with malformed filters.

        let mut wrong_syscall_name_filters = BTreeMap::new();
        wrong_syscall_name_filters.insert(
            "T1".to_string(),
            Filter::new(
                SeccompAction::Trap,
                SeccompAction::Allow,
                vec![SyscallRule::new("wrong_syscall".to_string(), None)],
            ),
        );

        assert_eq!(
            compiler.compile_blob(wrong_syscall_name_filters, false),
            Err(CompilationError::SyscallName(
                "wrong_syscall".to_string(),
                compiler.arch
            ))
        );

        let mut identical_action_filters = BTreeMap::new();
        identical_action_filters.insert(
            "T1".to_string(),
            Filter::new(SeccompAction::Allow, SeccompAction::Allow, vec![]),
        );

        assert_eq!(
            compiler.compile_blob(identical_action_filters, false),
            Err(CompilationError::IdenticalActions)
        );

        // Test with correct filters.
        let mut correct_filters = BTreeMap::new();
        correct_filters.insert(
            "Thread1".to_string(),
            Filter::new(
                SeccompAction::Trap,
                SeccompAction::Allow,
                vec![
                    SyscallRule::new("read".to_string(), None),
                    SyscallRule::new(
                        "futex".to_string(),
                        Some(vec![
                            Cond::new(1, Dword, Eq, 65).unwrap(),
                            Cond::new(2, Qword, Le, 80).unwrap(),
                        ]),
                    ),
                    SyscallRule::new(
                        "futex".to_string(),
                        Some(vec![
                            Cond::new(3, Dword, Eq, 65).unwrap(),
                            Cond::new(2, Qword, Le, 80).unwrap(),
                        ]),
                    ),
                ],
            ),
        );

        // We don't test the BPF compilation in this module.
        // This is done in the seccomp/lib.rs module.
        // Here, we only test the (Filter -> SeccompFilter) transformations. (High-level -> IR)
        assert!(compiler
            .compile_blob(correct_filters.clone(), false)
            .is_ok());
        // Also test with basic filtering on.
        assert!(compiler.compile_blob(correct_filters, true).is_ok());
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(
            format!("{}", CompilationError::IdenticalActions),
            "`filter_action` and `default_action` are equal."
        );
        assert_eq!(
            format!(
                "{}",
                CompilationError::Filter(FilterError::InvalidArgumentNumber)
            ),
            "The seccomp rule contains an invalid argument number."
        );
        assert_eq!(
            format!(
                "{}",
                CompilationError::SyscallName("asdsad".to_string(), TargetArch::x86_64)
            ),
            format!(
                "Invalid syscall name: {} for given arch: {}.",
                "asdsad", "x86_64"
            )
        );
    }
}
