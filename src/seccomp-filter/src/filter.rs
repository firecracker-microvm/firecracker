// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The checked form of a compiled filter, from which the installed program is composed.

use crate::bpf::{self, ProgramError};
use crate::features::{SeccompFeature, SeccompFeatures, UnknownSeccompFeature};
use crate::format::{BpfFilter, BpfFragment};

/// Part of a seccomp filter that is only needed when one of its features is enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterFragment {
    /// Features that enable this fragment; any one of them is sufficient.
    pub features: SeccompFeatures,
    /// Position independent BPF code. It falls through to the next fragment when its rule does
    /// not match the syscall being filtered.
    pub code: Vec<u64>,
}

/// The seccomp filter of one thread category.
///
/// `base` holds the rules that are always needed. When the filter has feature-gated parts, the
/// base does not return the default action itself but falls through to the code appended after it:
/// the `fragments` of the enabled features followed by the `epilogue`, which returns the default
/// action. [`SeccompFilter::compose`] assembles the program that gets installed on a thread.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeccompFilter {
    base: Vec<u64>,
    fragments: Vec<FilterFragment>,
    epilogue: Vec<u64>,
}

/// Errors in the parts of a compiled filter.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum FilterError {
    /// Filter fragment tagged with an unknown feature: {0}
    UnknownFeature(#[from] UnknownSeccompFeature),
    /// Filter fragment without a feature tag
    UntaggedFragment,
    /// Filter with fragments or an epilogue but without a base program
    MissingBase,
    /// Filter with fragments but without an epilogue
    MissingEpilogue,
    /// Invalid base program: {0}
    InvalidBase(ProgramError),
    /// Invalid fragment {0}: {1}
    InvalidFragment(usize, ProgramError),
    /// Invalid epilogue: {0}
    InvalidEpilogue(ProgramError),
    /// Invalid program with every fragment included: {0}
    InvalidProgram(ProgramError),
}

impl SeccompFilter {
    /// Create a filter from its parts.
    pub fn new(base: Vec<u64>, fragments: Vec<FilterFragment>, epilogue: Vec<u64>) -> Self {
        SeccompFilter {
            base,
            fragments,
            epilogue,
        }
    }

    /// Create a filter from a complete program that has no feature-gated parts.
    pub fn from_program(program: Vec<u64>) -> Self {
        SeccompFilter::new(program, Vec::new(), Vec::new())
    }

    /// The program of the rules that are always needed.
    pub fn base(&self) -> &[u64] {
        &self.base
    }

    /// The feature-gated parts.
    pub fn fragments(&self) -> &[FilterFragment] {
        &self.fragments
    }

    /// The code that ends the program when the filter has feature-gated parts.
    pub fn epilogue(&self) -> &[u64] {
        &self.epilogue
    }

    /// Whether composing this filter yields an empty program, i.e. no filter gets installed.
    pub fn is_empty(&self) -> bool {
        self.base.is_empty()
            && self.epilogue.is_empty()
            && self
                .fragments
                .iter()
                .all(|fragment| fragment.code.is_empty())
    }

    /// The features for which this filter has fragments.
    pub fn features(&self) -> SeccompFeatures {
        self.fragments
            .iter()
            .fold(SeccompFeatures::empty(), |set, fragment| {
                set | fragment.features
            })
    }

    /// Assemble the program for a microVM with `enabled` features: the base, the fragments that
    /// have at least one enabled feature and the epilogue.
    pub fn compose(&self, enabled: SeccompFeatures) -> Vec<u64> {
        let fragments = self
            .fragments
            .iter()
            .filter(|fragment| fragment.features.intersects(enabled));
        let mut program = Vec::with_capacity(
            self.base.len()
                + self.epilogue.len()
                + fragments
                    .clone()
                    .map(|fragment| fragment.code.len())
                    .sum::<usize>(),
        );
        program.extend_from_slice(&self.base);
        for fragment in fragments {
            program.extend_from_slice(&fragment.code);
        }
        program.extend_from_slice(&self.epilogue);
        program
    }

    /// Check that every program [`SeccompFilter::compose`] can assemble from this filter is one
    /// the kernel accepts and that each part behaves the same whichever fragments are included.
    ///
    /// A filter without fragments and epilogue is either empty, i.e. no filter is installed, or
    /// its base is a complete program. Otherwise every fragment needs a feature, there are a base
    /// program and an epilogue, the base and each fragment only jump inside themselves or to their
    /// own end, where the next part starts, the epilogue is a complete program on its own, and the
    /// program with every fragment included is within the kernel's limits. The last two make
    /// every composed program end with a return and every jump land inside it; the jump rule
    /// keeps a part from landing in the middle of whatever happens to follow it.
    pub fn validate(&self) -> Result<(), FilterError> {
        if self.fragments.is_empty() && self.epilogue.is_empty() {
            if self.base.is_empty() {
                return Ok(());
            }
            return bpf::validate(&self.base).map_err(FilterError::InvalidBase);
        }
        // Fragments are only ever reached through the base program, and a fragment nothing can
        // enable is a rule that silently never applies.
        if self.base.is_empty() {
            return Err(FilterError::MissingBase);
        }
        if self.epilogue.is_empty() {
            return Err(FilterError::MissingEpilogue);
        }
        if self
            .fragments
            .iter()
            .any(|fragment| fragment.features.is_empty())
        {
            return Err(FilterError::UntaggedFragment);
        }
        bpf::validate_part(&self.base).map_err(FilterError::InvalidBase)?;
        for (index, fragment) in self.fragments.iter().enumerate() {
            bpf::validate_part(&fragment.code)
                .map_err(|err| FilterError::InvalidFragment(index, err))?;
        }
        bpf::validate(&self.epilogue).map_err(FilterError::InvalidEpilogue)?;
        // Leaving fragments out only shortens the program.
        bpf::validate(&self.compose(SeccompFeatures::all())).map_err(FilterError::InvalidProgram)
    }
}

impl TryFrom<BpfFilter> for SeccompFilter {
    type Error = FilterError;

    /// Check the parts of a compiled filter as read from a filter file, see
    /// [`SeccompFilter::validate`].
    fn try_from(filter: BpfFilter) -> Result<Self, Self::Error> {
        let fragments = filter
            .fragments
            .into_iter()
            .map(|fragment| {
                if fragment.features.is_empty() {
                    return Err(FilterError::UntaggedFragment);
                }
                let features = fragment
                    .features
                    .iter()
                    .map(|name| name.parse::<SeccompFeature>())
                    .collect::<Result<SeccompFeatures, _>>()?;
                Ok(FilterFragment {
                    features,
                    code: fragment.code,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let filter = SeccompFilter::new(filter.base, fragments, filter.epilogue);
        filter.validate()?;
        Ok(filter)
    }
}

impl From<&SeccompFilter> for BpfFilter {
    /// The form of `filter` that is written to a filter file.
    fn from(filter: &SeccompFilter) -> Self {
        BpfFilter {
            base: filter.base.clone(),
            fragments: filter
                .fragments
                .iter()
                .map(|fragment| BpfFragment {
                    features: fragment
                        .features
                        .iter()
                        .map(|feature| feature.name().to_string())
                        .collect(),
                    code: fragment.code.clone(),
                })
                .collect(),
            epilogue: filter.epilogue.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::{BPF_JA, BPF_JEQ_K, BPF_LD_W_ABS, BPF_MAX_LEN, BPF_RET_K, insn};

    const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    fn ret(action: u32) -> u64 {
        insn(BPF_RET_K, 0, 0, action)
    }

    fn ld_nr() -> u64 {
        insn(BPF_LD_W_ABS, 0, 0, 0)
    }

    /// A position independent part allowing syscall `nr` and falling through otherwise.
    fn allow(nr: u32) -> Vec<u64> {
        vec![ld_nr(), insn(BPF_JEQ_K, 0, 1, nr), ret(SECCOMP_RET_ALLOW)]
    }

    fn fragment(features: &[&str], code: Vec<u64>) -> BpfFragment {
        BpfFragment {
            features: features.iter().map(|name| name.to_string()).collect(),
            code,
        }
    }

    fn tagged(features: SeccompFeatures, code: Vec<u64>) -> FilterFragment {
        FilterFragment { features, code }
    }

    #[test]
    fn test_try_from() {
        let serialized = BpfFilter {
            base: allow(1),
            fragments: vec![fragment(&["net", "hotplug"], allow(2))],
            epilogue: vec![ret(SECCOMP_RET_TRAP)],
        };
        let filter = SeccompFilter::try_from(serialized.clone()).unwrap();
        assert_eq!(
            filter,
            SeccompFilter::new(
                allow(1),
                vec![tagged(
                    SeccompFeatures::from(SeccompFeature::Net) | SeccompFeature::Hotplug,
                    allow(2)
                )],
                vec![ret(SECCOMP_RET_TRAP)],
            )
        );
        // Written back in bit order.
        assert_eq!(
            BpfFilter::from(&filter),
            BpfFilter {
                fragments: vec![fragment(&["hotplug", "net"], allow(2))],
                ..serialized.clone()
            }
        );

        // An entirely empty filter is how `--no-seccomp` style custom filters look.
        assert_eq!(
            SeccompFilter::try_from(BpfFilter::default()).unwrap(),
            SeccompFilter::default()
        );
        assert_eq!(
            SeccompFilter::try_from(BpfFilter {
                base: vec![ret(SECCOMP_RET_ALLOW)],
                ..Default::default()
            })
            .unwrap(),
            SeccompFilter::from_program(vec![ret(SECCOMP_RET_ALLOW)])
        );

        // Fragments tagged with a feature this crate does not know are rejected.
        assert_eq!(
            SeccompFilter::try_from(BpfFilter {
                fragments: vec![fragment(&["net", "warp-drive"], allow(2))],
                ..serialized.clone()
            })
            .unwrap_err(),
            FilterError::UnknownFeature(UnknownSeccompFeature("warp-drive".to_string()))
        );
        // So are fragments nothing can enable, and parts that no base program leads to.
        assert_eq!(
            SeccompFilter::try_from(BpfFilter {
                fragments: vec![fragment(&[], allow(2))],
                ..serialized.clone()
            })
            .unwrap_err(),
            FilterError::UntaggedFragment
        );
        assert_eq!(
            SeccompFilter::try_from(BpfFilter {
                epilogue: vec![ret(SECCOMP_RET_TRAP)],
                ..Default::default()
            })
            .unwrap_err(),
            FilterError::MissingBase
        );
        // The parts are checked too.
        assert_eq!(
            SeccompFilter::try_from(BpfFilter {
                epilogue: vec![],
                ..serialized
            })
            .unwrap_err(),
            FilterError::MissingEpilogue
        );
    }

    #[test]
    fn test_validate() {
        let trap = vec![ret(SECCOMP_RET_TRAP)];
        let net = SeccompFeatures::from(SeccompFeature::Net);
        let pmem = SeccompFeatures::from(SeccompFeature::Pmem);
        let filter = SeccompFilter::new(
            allow(1),
            vec![tagged(net, allow(2)), tagged(pmem, allow(3))],
            trap.clone(),
        );
        filter.validate().unwrap();
        // Whichever fragments are included, the kernel takes the program.
        for enabled in [SeccompFeatures::empty(), net, pmem, net | pmem] {
            bpf::validate(&filter.compose(enabled)).unwrap();
        }

        // A program without fragments must be complete: a base that falls through its end is not.
        assert_eq!(
            SeccompFilter::from_program(allow(1)).validate(),
            Err(FilterError::InvalidBase(ProgramError::InvalidJump(1)))
        );
        assert_eq!(
            SeccompFilter::from_program(vec![ld_nr()]).validate(),
            Err(FilterError::InvalidBase(ProgramError::LastNotReturn))
        );
        // Fragments need a feature.
        assert_eq!(
            SeccompFilter::new(
                allow(1),
                vec![tagged(SeccompFeatures::empty(), allow(2))],
                trap.clone()
            )
            .validate(),
            Err(FilterError::UntaggedFragment)
        );
        // A base or fragment jumping past its end would land on different code depending on the
        // enabled features, or outside of the program.
        let skips_two = vec![ld_nr(), insn(BPF_JEQ_K, 0, 2, 2), ret(SECCOMP_RET_ALLOW)];
        assert_eq!(
            SeccompFilter::new(skips_two.clone(), vec![tagged(net, allow(2))], trap.clone())
                .validate(),
            Err(FilterError::InvalidBase(ProgramError::InvalidJump(1)))
        );
        assert_eq!(
            SeccompFilter::new(
                allow(1),
                vec![tagged(net, allow(2)), tagged(pmem, skips_two)],
                trap.clone()
            )
            .validate(),
            Err(FilterError::InvalidFragment(
                1,
                ProgramError::InvalidJump(1)
            ))
        );
        // The epilogue ends every program, so it must be complete on its own.
        assert_eq!(
            SeccompFilter::new(
                allow(1),
                vec![tagged(net, allow(2))],
                vec![insn(BPF_JA, 0, 0, 0), ld_nr()]
            )
            .validate(),
            Err(FilterError::InvalidEpilogue(ProgramError::LastNotReturn))
        );
        // And the longest program must fit in the kernel's limit.
        let mut long_base = vec![ld_nr(); BPF_MAX_LEN - 3];
        long_base.extend(allow(1));
        assert_eq!(
            SeccompFilter::new(long_base, vec![tagged(net, allow(2))], trap).validate(),
            Err(FilterError::InvalidProgram(ProgramError::TooLong(
                BPF_MAX_LEN + 4
            )))
        );
    }

    #[test]
    fn test_compose() {
        let empty = SeccompFilter::default();
        assert!(empty.is_empty());
        assert!(empty.compose(SeccompFeatures::all()).is_empty());

        let plain = SeccompFilter::from_program(vec![1, 2, 3]);
        assert!(!plain.is_empty());
        assert_eq!(plain.features(), SeccompFeatures::empty());
        assert_eq!(plain.compose(SeccompFeatures::empty()), vec![1, 2, 3]);
        assert_eq!(plain.compose(SeccompFeatures::all()), vec![1, 2, 3]);

        let filter = SeccompFilter::new(
            vec![1, 2],
            vec![
                FilterFragment {
                    features: SeccompFeature::Net.into(),
                    code: vec![10, 11],
                },
                FilterFragment {
                    features: SeccompFeatures::from(SeccompFeature::Pmem)
                        | SeccompFeature::MemoryHotplug,
                    code: vec![20],
                },
            ],
            vec![3],
        );
        assert!(!filter.is_empty());
        assert_eq!(filter.base(), [1, 2]);
        assert_eq!(filter.fragments().len(), 2);
        assert_eq!(filter.epilogue(), [3]);
        assert_eq!(
            filter.features(),
            SeccompFeatures::from(SeccompFeature::Net)
                | SeccompFeature::Pmem
                | SeccompFeature::MemoryHotplug
        );
        assert_eq!(filter.compose(SeccompFeatures::empty()), vec![1, 2, 3]);
        assert_eq!(
            filter.compose(SeccompFeature::Net.into()),
            vec![1, 2, 10, 11, 3]
        );
        // Any one of a fragment's features enables it.
        assert_eq!(
            filter.compose(SeccompFeature::Pmem.into()),
            vec![1, 2, 20, 3]
        );
        assert_eq!(
            filter.compose(SeccompFeature::MemoryHotplug.into()),
            vec![1, 2, 20, 3]
        );
        assert_eq!(filter.compose(SeccompFeature::Block.into()), vec![1, 2, 3]);
        assert_eq!(
            filter.compose(SeccompFeatures::all()),
            vec![1, 2, 10, 11, 20, 3]
        );
    }
}
