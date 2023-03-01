// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use utils::get_page_size;

use crate::handler::HandlerError;
use crate::Error;

#[derive(Default)]
pub struct UffdPrefaulter {
    bytes_after: usize,
}

impl UffdPrefaulter {
    pub fn new(after: usize) -> Result<Self, Error> {
        let page_size = get_page_size()
            .map_err(HandlerError::PageSize)
            .map_err(Error::UffdHandler)?;

        Ok(UffdPrefaulter {
            bytes_after: after
                .checked_mul(page_size)
                .ok_or_else(|| Error::InvalidAmount(after))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_prefaulter() {
        let page_size = get_page_size().unwrap();
        let prefaulter = UffdPrefaulter::new(1024).unwrap();
        assert_eq!(prefaulter.bytes_after, 1024 * page_size);

        let res = UffdPrefaulter::new(usize::MAX);
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap().to_string(),
            Error::InvalidAmount(usize::MAX).to_string()
        );
    }
}
