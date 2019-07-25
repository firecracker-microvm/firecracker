// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter, Result};

/// Errors associated with the operations allowed on a memory balloon device.
#[derive(Debug, PartialEq)]
pub enum BalloonError {
    /// Epoll configuration not found.
    EpollHandlerNotFound,
    /// Tried to insert a balloon after booting.
    InsertNotAllowedPostBoot,
    /// Tried updating a balloon that doesn't exist.
    UpdatedInexistentDevice,
}

impl Display for BalloonError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::BalloonError::*;
        match *self {
            EpollHandlerNotFound => write!(f, "Epoll handler not found."),
            InsertNotAllowedPostBoot => {
                write!(f, "Inserting a balloon device not allowed after booting.")
            }
            UpdatedInexistentDevice => {
                write!(f, "Not allowed to update an inexistent balloon device.")
            }
        }
    }
}

/// Use this structure to set up the Balloon Device before booting the kernel.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BalloonConfig {
    /// The number of pages that should be in the balloon device.
    num_pages: usize,
    /// Whether the balloon device should deflate when the guest runs out
    /// of memory, or not.
    deflate_on_oom: bool,
    /// Whether the host should be told of the pages from a deflate.
    must_tell_host: bool,
}

impl BalloonConfig {
    /// Creates a new balloon configuration with a specified target number of pages.
    pub fn new(num_pages: usize, must_tell_host: bool, deflate_on_oom: bool) -> BalloonConfig {
        BalloonConfig {
            num_pages,
            must_tell_host,
            deflate_on_oom,
        }
    }

    /// Returns the number of pages that should be in the balloon.
    pub fn num_pages(&self) -> usize {
        self.num_pages
    }

    /// Returns whether the balloon should deflate on an out of memory condition.
    pub fn must_tell_host(&self) -> bool {
        self.must_tell_host
    }

    /// Returns whether the balloon should deflate on an Out Of Memory condition.
    pub fn deflate_on_oom(&self) -> bool {
        self.deflate_on_oom
    }
}

/// Wrapper for a collection that holds [`BalloonConfig`](struct.BalloonConfig.html)
/// objects. Since there is at most one balloon per virtual machine, it makes sense
/// to store our configs in an Option.
pub type BalloonConfigs = Option<BalloonConfig>;

/// Use this structure to update the balloon device after booting the kernel.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BalloonUpdateConfig {
    /// The number of pages that should be in the balloon.
    num_pages: usize,
}

impl BalloonUpdateConfig {
    /// Creates a new balloon configuration with a specified target number of pages.
    pub fn new(num_pages: usize) -> BalloonUpdateConfig {
        BalloonUpdateConfig { num_pages }
    }

    /// Returns the number of pages that should be in the balloon device.
    pub fn num_pages(self) -> usize {
        self.num_pages
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_balloon_error_format() {
        use BalloonError::*;
        assert_eq!(
            format!("{}", EpollHandlerNotFound),
            "Epoll handler not found."
        );
        assert_eq!(
            format!("{}", InsertNotAllowedPostBoot),
            "Inserting a balloon device not allowed after booting."
        );
        assert_eq!(
            format!("{}", UpdatedInexistentDevice),
            "Not allowed to update an inexistent balloon device."
        );
    }

}
