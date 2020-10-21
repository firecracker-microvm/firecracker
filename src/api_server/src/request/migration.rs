// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};
use crate::request::Body;
#[cfg(target_arch = "x86_64")]
use crate::request::{Method, StatusCode};
#[cfg(target_arch = "x86_64")]
use vmm::vmm_config::migration::{AcceptMigrationParams, StartMigrationParams};

#[cfg(target_arch = "x86_64")]
pub fn parse_put_migration(
    body: &Body,
    request_type_from_path: Option<&&str>,
) -> Result<ParsedRequest, Error> {
    match request_type_from_path {
        Some(&request_type) => match request_type {
            "accept" => Ok(ParsedRequest::new_sync(VmmAction::AcceptMigration(
                serde_json::from_slice::<AcceptMigrationParams>(body.raw())
                    .map_err(Error::SerdeJson)?,
            ))),
            "start" => Ok(ParsedRequest::new_sync(VmmAction::StartMigration(
                serde_json::from_slice::<StartMigrationParams>(body.raw())
                    .map_err(Error::SerdeJson)?,
            ))),
            _ => Err(Error::InvalidPathMethod(
                format!("/migration/{}", request_type),
                Method::Put,
            )),
        },
        None => Err(Error::Generic(
            StatusCode::BadRequest,
            "Missing snapshot operation type.".to_string(),
        )),
    }
}
