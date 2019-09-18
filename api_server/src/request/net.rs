// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/*

use std::result;

use vmm::vmm_config::net::{NetworkInterfaceConfig, NetworkInterfaceUpdateConfig};
use vmm::VmmAction;

impl NetworkInterfaceConfig {
    fn into_parsed_request(self, id_from_path: String) -> result::Result<ParsedRequest, String> {
        let id_from_path = id_from_path.unwrap_or_default();
        if id_from_path != self.iface_id {
            return Err(String::from(
                "The id from the path does not match the id from the body!",
            ));
        }
        Ok(ParsedRequest::Sync(VmmAction::InsertNetworkDevice(self)))
    }
}

impl NetworkInterfaceUpdateConfig {
    fn into_parsed_request(self, id_from_path: String) -> result::Result<ParsedRequest, String> {
        let id_from_path = id_from_path.unwrap_or_default();
        if id_from_path != self.iface_id {
            return Err(String::from(
                "The id from the path does not match the id from the body!",
            ));
        }
        Ok(ParsedRequest::Sync(VmmAction::UpdateNetworkInterface(self)))
    }
}
*/
