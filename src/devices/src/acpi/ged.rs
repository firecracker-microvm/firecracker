// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use acpi::{aml, Aml};

/// Generic Event Device is the ACPI mechanism used
/// for delivering events (notifications) to various ACPI devices in the
/// system, such as VMGenID
pub struct AcpiGenericEventDevice {
    vmgenid_irq: u32,
}

impl AcpiGenericEventDevice {
    pub fn new(vmgenid_irq: u32) -> Self {
        AcpiGenericEventDevice { vmgenid_irq }
    }
}

impl Aml for AcpiGenericEventDevice {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) {
        aml::Device::new(
            "_SB_.GED_".into(),
            vec![
                &aml::Name::new("_HID".into(), &"ACPI0013"),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![&aml::Interrupt::new(
                        true,
                        true,
                        false,
                        false,
                        self.vmgenid_irq,
                    )]),
                ),
                &aml::Method::new(
                    "_EVT".into(),
                    1,
                    true,
                    vec![&aml::If::new(
                        &aml::Equal::new(&aml::Arg(0), &(self.vmgenid_irq as u8)),
                        vec![&aml::Notify::new(
                            &aml::Path::new("\\_SB_.VGEN"),
                            &0x80usize,
                        )],
                    )],
                ),
            ],
        )
        .append_aml_bytes(v);
    }
}
