// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::VmmAction;
use logger::{Metric, METRICS};
use request::Body;
use request::Error;
use request::StatusCode;

use request::checked_id;
use request::ParsedRequest;
use vmm::vmm_config::net::{NetworkInterfaceConfig, NetworkInterfaceUpdateConfig};

pub fn parse_put_net(
    maybe_body: Option<&Body>,
    id_from_path: Option<&&str>,
) -> Result<ParsedRequest, Error> {
    METRICS.patch_api_requests.network_count.inc();
    let id = match id_from_path {
        Some(&id) => checked_id(id)?,
        None => {
            return Err(Error::EmptyID);
        }
    };

    if let Some(body) = maybe_body {
        let netif = serde_json::from_slice::<NetworkInterfaceConfig>(body.raw()).map_err(|e| {
            METRICS.put_api_requests.network_fails.inc();
            Error::SerdeJson(e)
        })?;
        if id != netif.iface_id.as_str() {
            return Err(Error::Generic(
                StatusCode::BadRequest,
                "The id from the path does not match the id from the body!".to_string(),
            ));
        }
        Ok(ParsedRequest::Sync(VmmAction::InsertNetworkDevice(netif)))
    } else {
        Err(Error::Generic(
            StatusCode::BadRequest,
            "Empty PUT request.".to_string(),
        ))
    }
}

pub fn parse_patch_net(
    maybe_body: Option<&Body>,
    id_from_path: Option<&&str>,
) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.network_count.inc();
    let id = match id_from_path {
        Some(&id) => checked_id(id)?,
        None => {
            return Err(Error::EmptyID);
        }
    };

    if let Some(body) = maybe_body {
        let netif =
            serde_json::from_slice::<NetworkInterfaceUpdateConfig>(body.raw()).map_err(|e| {
                METRICS.patch_api_requests.network_fails.inc();
                Error::SerdeJson(e)
            })?;
        if id != netif.iface_id {
            return Err(Error::Generic(
                StatusCode::BadRequest,
                "The id from the path does not match the id from the body!".to_string(),
            ));
        }
        Ok(ParsedRequest::Sync(VmmAction::UpdateNetworkInterface(
            netif,
        )))
    } else {
        Err(Error::Generic(
            StatusCode::BadRequest,
            "Empty PATCH request.".to_string(),
        ))
    }
}
