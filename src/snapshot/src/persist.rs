// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines an abstract interface for saving/restoring a component from state.

/// An abstract interface for saving/restoring a component using a specific state.
pub trait Persist<'a>
where
    Self: Sized,
{
    /// The type of the object representing the state of the component.
    type State;
    /// The type of the object holding the constructor arguments.
    type ConstructorArgs;
    /// The type of the error that can occur while constructing the object.
    type Error;

    /// Returns the current state of the component.
    fn save(&self) -> Self::State;
    /// Constructs a component from a specified state.
    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error>;
}
