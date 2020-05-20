// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Errors associated with the `Init` struct.
#[derive(Debug)]
pub enum Error {
    AlreadyInitialized,
    InitializationInProgress,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            Error::AlreadyInitialized => "The component is already initialized.".to_string(),
            Error::InitializationInProgress => {
                "The component is initializing. Can't perform the requested action right now."
                    .to_string()
            }
        };
        f.write_str(&msg)
    }
}

/// A helper structure which can be used to run a one-time initialization.
pub struct Init {
    state: AtomicUsize,
}

impl Init {
    const UNINITIALIZED: usize = 0;
    const INITIALIZING: usize = 1;
    const INITIALIZED: usize = 2;

    /// Creates a new instance of `Init`.
    pub const fn new() -> Self {
        Self {
            state: AtomicUsize::new(Self::UNINITIALIZED),
        }
    }

    /// Performs an initialization routine.
    ///
    /// The given closure will be executed if the current state is `UNINITIALIZED`.
    /// Otherwise an Error will be returned.
    ///
    /// If the closure returns `true`, the state will be changed to `INITIALIZED`.
    /// If the closure returns `false`, the state will remain `UNINITIALIZED`.
    pub fn call_init<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnOnce() -> bool,
    {
        match self
            .state
            .compare_and_swap(Self::UNINITIALIZED, Self::INITIALIZING, Ordering::SeqCst)
        {
            Self::INITIALIZING => {
                return Err(Error::InitializationInProgress);
            }
            Self::INITIALIZED => {
                return Err(Error::AlreadyInitialized);
            }
            _ => {}
        }

        let state = if f() {
            Self::INITIALIZED
        } else {
            Self::UNINITIALIZED
        };

        self.state.store(state, Ordering::SeqCst);

        Ok(())
    }

    /// Checks if the current state is `INITIALIZED`.
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.state.load(Ordering::Relaxed) == Self::INITIALIZED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_init_with_true() {
        let init = Init::new();
        assert!(init.call_init(|| { true }).is_ok());
        assert!(init.state.load(Ordering::Relaxed) == Init::INITIALIZED);
    }

    #[test]
    fn test_call_init_with_false() {
        let init = Init::new();
        assert!(init.call_init(|| { false }).is_ok());
        assert!(init.state.load(Ordering::Relaxed) == Init::UNINITIALIZED);
    }

    #[test]
    fn test_call_init_errors() {
        let init = Init::new();

        init.state.store(Init::INITIALIZED, Ordering::SeqCst);
        assert!(init.call_init(|| { true }).is_err());

        init.state.store(Init::INITIALIZING, Ordering::SeqCst);
        assert!(init.call_init(|| { true }).is_err());
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(
            format!("{}", Error::InitializationInProgress),
            "The component is initializing. Can't perform the requested action right now."
        );
        assert_eq!(
            format!("{}", Error::AlreadyInitialized),
            "The component is already initialized."
        );
    }
}
