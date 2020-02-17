// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Simple abstraction of a state machine.
///
/// `StateMachine<T>` is a wrapper over `T` that also encodes state information for `T`.
///
/// Each state for `T` is represented by a `StateFn<T>` which is a function that acts as
/// the state handler for that particular state of `T`.
///
/// `StateFn<T>` returns exactly one other `StateMachine<T>` thus each state gets clearly
/// defined transitions to other states.
pub struct StateMachine<T> {
    function: Option<StateFn<T>>,
}

/// Type representing a state handler of a `StateMachine<T>` machine. Each state handler
/// is a function from `T` that handles a specific state of `T`.
type StateFn<T> = fn(&mut T) -> StateMachine<T>;

impl<T> StateMachine<T> {
    /// Creates a new state wrapper.
    ///
    /// # Arguments
    ///
    /// `function` - the state handler for this state.
    ///
    pub fn new(function: Option<StateFn<T>>) -> StateMachine<T> {
        StateMachine { function }
    }

    /// Creates a new state wrapper that has further possible transitions.
    ///
    /// # Arguments
    ///
    /// `function` - the state handler for this state.
    ///
    pub fn next(function: StateFn<T>) -> StateMachine<T> {
        StateMachine::new(Some(function))
    }

    /// Creates a new state wrapper that has no further transitions. The state machine
    /// will finish after running this handler.
    ///
    /// # Arguments
    ///
    /// `function` - the state handler for this last state.
    ///
    pub fn finish() -> StateMachine<T> {
        StateMachine::new(None)
    }

    /// Runs a state machine for `T` starting from the provided state.
    ///
    /// # Arguments
    ///
    /// `machine` - a mutable reference to the object running through the various states.
    /// `starting_state_fn` - a `fn(&mut T) -> StateMachine<T>` that should be the handler for
    ///                       the initial state.
    ///
    pub fn run(machine: &mut T, starting_state_fn: StateFn<T>) {
        // Start off in the `starting_state` state.
        let mut state_machine = StateMachine::new(Some(starting_state_fn));
        // While current state is not a final/end state, keep churning.
        while let Some(state_fn) = state_machine.function {
            // Run the current state handler, and get the next one.
            state_machine = state_fn(machine);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // DummyMachine with states `s1`, `s2` and `s3`.
    struct DummyMachine {
        private_data_s1: bool,
        private_data_s2: bool,
        private_data_s3: bool,
    }

    impl DummyMachine {
        fn new() -> Self {
            DummyMachine {
                private_data_s1: false,
                private_data_s2: false,
                private_data_s3: false,
            }
        }

        // DummyMachine functions here.

        // Simple state-machine: start->s1->s2->s3->done.
        fn run(&mut self) {
            // Verify the machine has not run yet.
            assert!(!self.private_data_s1);
            assert!(!self.private_data_s2);
            assert!(!self.private_data_s3);

            // Run the state-machine.
            StateMachine::run(self, Self::s1);

            // Verify the machine went through all states.
            assert!(self.private_data_s1);
            assert!(self.private_data_s2);
            assert!(self.private_data_s3);
        }

        fn s1(&mut self) -> StateMachine<Self> {
            // Verify private data mutates along with the states.
            assert!(!self.private_data_s1);
            self.private_data_s1 = true;
            StateMachine::next(Self::s2)
        }

        fn s2(&mut self) -> StateMachine<Self> {
            // Verify private data mutates along with the states.
            assert!(!self.private_data_s2);
            self.private_data_s2 = true;
            StateMachine::next(Self::s3)
        }

        fn s3(&mut self) -> StateMachine<Self> {
            // Verify private data mutates along with the states.
            assert!(!self.private_data_s3);
            self.private_data_s3 = true;
            // The machine ends here, adding `s1` as next state to validate this.
            StateMachine::finish()
        }
    }

    #[test]
    fn test_sm() {
        let mut machine = DummyMachine::new();
        machine.run();
    }
}
