// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0<Paste>

/*impl GenerateHyperResponse for VmConfig {
    fn generate_response(&self) -> Response {
        let vcpu_count = self.vcpu_count.unwrap_or(1);
        let mem_size = self.mem_size_mib.unwrap_or(128);
        let ht_enabled = self.ht_enabled.unwrap_or(false);
        let cpu_template = self
            .cpu_template
            .map_or("Uninitialized".to_string(), |c| c.to_string());

        json_response(
            StatusCode::Ok,
            format!(
                "{{ \"vcpu_count\": {:?}, \"mem_size_mib\": {:?},  \"ht_enabled\": {:?},  \"cpu_template\": {:?} }}",
                vcpu_count, mem_size, ht_enabled, cpu_template
            ),
        )
    }
}*/
