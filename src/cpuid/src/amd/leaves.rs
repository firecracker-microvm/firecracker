// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::similar_names, clippy::module_name_repetitions)]

#[allow(clippy::wildcard_imports)]
use super::registers::*;
use crate::Leaf;

/// Leaf 07H
pub type Leaf7 = Leaf<Leaf7Eax, Leaf7Ebx, Leaf7Ecx, Leaf7Edx>;

/// Leaf 80000000H
pub type Leaf80000000 = Leaf<Leaf80000000Eax, Leaf80000000Ebx, Leaf80000000Ecx, Leaf80000000Edx>;

/// Leaf 80000001H
pub type Leaf80000001 = Leaf<Leaf80000001Eax, Leaf80000001Ebx, Leaf80000001Ecx, Leaf80000001Edx>;

/// Leaf 80000008H
pub type Leaf80000008 = Leaf<Leaf80000008Eax, Leaf80000008Ebx, Leaf80000008Ecx, Leaf80000008Edx>;

/// Leaf 8000001DH
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf8000001d<'a>(pub Vec<&'a Leaf8000001dSubleaf>);

/// Leaf 8000001DH
#[derive(Debug, PartialEq, Eq)]
pub struct Leaf8000001dMut<'a>(pub Vec<&'a mut Leaf8000001dSubleaf>);

/// Leaf 8000001DH sub-leaf
pub type Leaf8000001dSubleaf =
    Leaf<Leaf8000001dEax, Leaf8000001dEbx, Leaf8000001dEcx, Leaf8000001dEdx>;

/// Leaf 8000001EH
pub type Leaf8000001e = Leaf<Leaf8000001eEax, Leaf8000001eEbx, Leaf8000001eEcx, Leaf8000001eEdx>;
