// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The checked form of a compiled filter, from which the installed program is composed.

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
}

impl TryFrom<BpfFilter> for SeccompFilter {
    type Error = FilterError;

    /// Check the parts of a compiled filter as read from a filter file.
    fn try_from(filter: BpfFilter) -> Result<Self, Self::Error> {
        // Fragments are only ever reached through the base program, and a fragment nothing can
        // enable is a rule that silently never applies.
        if filter.base.is_empty() && !(filter.fragments.is_empty() && filter.epilogue.is_empty()) {
            return Err(FilterError::MissingBase);
        }
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
        Ok(SeccompFilter::new(filter.base, fragments, filter.epilogue))
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

    fn fragment(features: &[&str], code: Vec<u64>) -> BpfFragment {
        BpfFragment {
            features: features.iter().map(|name| name.to_string()).collect(),
            code,
        }
    }

    #[test]
    fn test_try_from() {
        let serialized = BpfFilter {
            base: vec![0; 2],
            fragments: vec![fragment(&["net", "hotplug"], vec![1; 3])],
            epilogue: vec![2],
        };
        let filter = SeccompFilter::try_from(serialized.clone()).unwrap();
        assert_eq!(
            filter,
            SeccompFilter::new(
                vec![0; 2],
                vec![FilterFragment {
                    features: SeccompFeatures::from(SeccompFeature::Net) | SeccompFeature::Hotplug,
                    code: vec![1; 3],
                }],
                vec![2],
            )
        );
        // Written back in bit order.
        assert_eq!(
            BpfFilter::from(&filter),
            BpfFilter {
                fragments: vec![fragment(&["hotplug", "net"], vec![1; 3])],
                ..serialized
            }
        );

        // An entirely empty filter is how `--no-seccomp` style custom filters look.
        assert_eq!(
            SeccompFilter::try_from(BpfFilter::default()).unwrap(),
            SeccompFilter::default()
        );
        assert_eq!(
            SeccompFilter::try_from(BpfFilter {
                base: vec![3],
                ..Default::default()
            })
            .unwrap(),
            SeccompFilter::from_program(vec![3])
        );

        // Fragments tagged with a feature this crate does not know are rejected.
        assert_eq!(
            SeccompFilter::try_from(BpfFilter {
                base: vec![0; 2],
                fragments: vec![fragment(&["net", "warp-drive"], vec![1])],
                epilogue: vec![2],
            })
            .unwrap_err(),
            FilterError::UnknownFeature(UnknownSeccompFeature("warp-drive".to_string()))
        );
        // So are fragments nothing can enable, and parts that no base program leads to.
        assert_eq!(
            SeccompFilter::try_from(BpfFilter {
                base: vec![0; 2],
                fragments: vec![fragment(&[], vec![1])],
                epilogue: vec![2],
            })
            .unwrap_err(),
            FilterError::UntaggedFragment
        );
        assert_eq!(
            SeccompFilter::try_from(BpfFilter {
                epilogue: vec![2],
                ..Default::default()
            })
            .unwrap_err(),
            FilterError::MissingBase
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
