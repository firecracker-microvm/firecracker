// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod actions;
pub mod boot_source;
pub mod drive;
pub mod logger;
pub mod machine_configuration;
pub mod net;
#[cfg(feature = "vsock")]
pub mod vsock;

use serde_json::Value;
use std::result;

use hyper;
use hyper::{Method, StatusCode};

use http_service::{empty_response, json_fault_message, json_response};
use vmm::{ErrorKind, OutcomeReceiver, VmmAction, VmmActionError, VmmData};

#[allow(clippy::large_enum_variant)]
pub enum ParsedRequest {
    GetInstanceInfo,
    GetMMDS,
    PatchMMDS(Value),
    PutMMDS(Value),
    Sync(VmmAction, OutcomeReceiver),
}

pub trait IntoParsedRequest {
    fn into_parsed_request(
        self,
        resource_id: Option<String>,
        method: Method,
    ) -> result::Result<ParsedRequest, String>;
}

// Sync requests have outcomes which implement this trait. The idea is for each outcome to be a
// struct which is cheaply and quickly instantiated by the VMM thread, then passed back the the API
// thread, and then unpacked into a http response using the implementation of
// the generate_response() method.
pub trait GenerateHyperResponse {
    fn generate_response(&self) -> hyper::Response;
}

impl GenerateHyperResponse for result::Result<VmmData, VmmActionError> {
    fn generate_response(&self) -> hyper::Response {
        match *self {
            Ok(ref data) => data.generate_response(),
            Err(ref error) => error.generate_response(),
        }
    }
}

impl GenerateHyperResponse for VmmData {
    fn generate_response(&self) -> hyper::Response {
        match *self {
            VmmData::MachineConfiguration(ref machine_config) => machine_config.generate_response(),
            VmmData::Empty => empty_response(StatusCode::NoContent),
        }
    }
}

impl GenerateHyperResponse for VmmActionError {
    fn generate_response(&self) -> hyper::Response {
        use self::ErrorKind::*;

        let status_code = match self.get_kind() {
            User => StatusCode::BadRequest,
            Internal => StatusCode::InternalServerError,
        };

        json_response(status_code, json_fault_message(self.to_string()))
    }
}

#[cfg(test)]
impl PartialEq for ParsedRequest {
    fn eq(&self, other: &ParsedRequest) -> bool {
        match (self, other) {
            (
                &ParsedRequest::Sync(ref sync_req, _),
                &ParsedRequest::Sync(ref other_sync_req, _),
            ) => sync_req == other_sync_req,
            (&ParsedRequest::GetInstanceInfo, &ParsedRequest::GetInstanceInfo) => true,
            (&ParsedRequest::GetMMDS, &ParsedRequest::GetMMDS) => true,
            (&ParsedRequest::PutMMDS(ref val), &ParsedRequest::PutMMDS(ref other_val)) => {
                val == other_val
            }
            (&ParsedRequest::PatchMMDS(ref val), &ParsedRequest::PatchMMDS(ref other_val)) => {
                val == other_val
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate arch;
    extern crate devices;
    extern crate kernel;
    extern crate memory_model;
    extern crate net_util;

    use self::devices::virtio::net::Error as VirtioNetError;
    use self::memory_model::GuestMemoryError;
    use self::net_util::TapError;
    use super::*;

    use std::io;

    use vmm::vmm_config::boot_source::BootSourceConfigError;
    use vmm::vmm_config::drive::DriveError;
    use vmm::vmm_config::instance_info::StartMicrovmError;
    use vmm::vmm_config::logger::LoggerConfigError;
    use vmm::vmm_config::machine_config::{VmConfig, VmConfigError};
    use vmm::vmm_config::net::NetworkInterfaceError;

    use futures::{Future, Stream};
    use hyper::{Body, Response};
    use serde_json;
    use std;

    fn get_body(
        response: Response<Body>,
    ) -> std::result::Result<serde_json::Value, serde_json::Error> {
        let body = response
            .body()
            .map_err(|_| ())
            .fold(vec![], |mut acc, chunk| {
                acc.extend_from_slice(&chunk);
                Ok(acc)
            })
            .and_then(|v| String::from_utf8(v).map_err(|_| ()));
        serde_json::from_str::<Value>(body.wait().unwrap().as_ref())
    }

    fn check_error_response(error: VmmActionError, status_code: StatusCode) {
        let hyper_resp = Err(error).generate_response();
        assert_eq!(hyper_resp.status(), status_code);
        assert!(get_body(hyper_resp).is_ok());
    }

    #[test]
    fn test_generate_response() {
        // Test OK Empty response from VMM.
        let vmm_resp = Ok(VmmData::Empty);
        let hyper_resp = vmm_resp.generate_response();
        assert_eq!(hyper_resp.status(), StatusCode::NoContent);
        // assert that the body is empty. When the JSON is empty, serde returns and EOF error.
        let body_err = get_body(hyper_resp).unwrap_err();
        assert_eq!(
            body_err.to_string(),
            "EOF while parsing a value at line 1 column 0"
        );

        // Test OK response from VMM that contains the Machine Configuration.
        let vmm_resp = Ok(VmmData::MachineConfiguration(VmConfig::default()));
        let hyper_resp = vmm_resp.generate_response();
        assert_eq!(hyper_resp.status(), StatusCode::Ok);
        let vm_config_json = r#"{
            "vcpu_count": 1,
            "mem_size_mib": 128,
            "ht_enabled": false,
            "cpu_template": "Uninitialized"
        }"#;
        let vm_config_json: serde_json::Value = serde_json::from_str(vm_config_json).unwrap();
        assert_eq!(get_body(hyper_resp).unwrap(), vm_config_json);

        // Tests Error Cases
        // Tests for BootSource Errors.
        let vmm_resp =
            VmmActionError::BootSource(ErrorKind::User, BootSourceConfigError::InvalidKernelPath);
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp = VmmActionError::BootSource(
            ErrorKind::User,
            BootSourceConfigError::InvalidKernelCommandLine,
        );
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp = VmmActionError::BootSource(
            ErrorKind::User,
            BootSourceConfigError::UpdateNotAllowedPostBoot,
        );
        check_error_response(vmm_resp, StatusCode::BadRequest);

        // Tests for DriveConfig Errors.
        let vmm_resp =
            VmmActionError::DriveConfig(ErrorKind::User, DriveError::CannotOpenBlockDevice);
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp =
            VmmActionError::DriveConfig(ErrorKind::User, DriveError::InvalidBlockDeviceID);
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp =
            VmmActionError::DriveConfig(ErrorKind::User, DriveError::InvalidBlockDevicePath);
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp =
            VmmActionError::DriveConfig(ErrorKind::User, DriveError::BlockDevicePathAlreadyExists);
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp =
            VmmActionError::DriveConfig(ErrorKind::User, DriveError::OperationNotAllowedPreBoot);
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp =
            VmmActionError::DriveConfig(ErrorKind::User, DriveError::RootBlockDeviceAlreadyAdded);
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp =
            VmmActionError::DriveConfig(ErrorKind::User, DriveError::UpdateNotAllowedPostBoot);
        check_error_response(vmm_resp, StatusCode::BadRequest);

        // Tests for Logger Errors.
        let vmm_resp = VmmActionError::Logger(
            ErrorKind::User,
            LoggerConfigError::InitializationFailure(
                "Could not open logging fifo: dummy".to_string(),
            ),
        );
        check_error_response(vmm_resp, StatusCode::BadRequest);

        // Tests for MachineConfig Errors.
        let vmm_resp =
            VmmActionError::MachineConfig(ErrorKind::User, VmConfigError::InvalidVcpuCount);
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp =
            VmmActionError::MachineConfig(ErrorKind::User, VmConfigError::InvalidMemorySize);
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp =
            VmmActionError::MachineConfig(ErrorKind::User, VmConfigError::UpdateNotAllowedPostBoot);
        check_error_response(vmm_resp, StatusCode::BadRequest);

        // Tests for NetworkConfig Errors.
        let vmm_resp = VmmActionError::NetworkConfig(
            ErrorKind::User,
            NetworkInterfaceError::OpenTap(TapError::OpenTun(io::Error::from_raw_os_error(22))),
        );
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp = VmmActionError::NetworkConfig(
            ErrorKind::User,
            NetworkInterfaceError::GuestMacAddressInUse(String::from("12:34:56:78:9a:bc")),
        );
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp = VmmActionError::NetworkConfig(
            ErrorKind::User,
            NetworkInterfaceError::UpdateNotAllowedPostBoot,
        );
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp = VmmActionError::NetworkConfig(
            ErrorKind::User,
            NetworkInterfaceError::HostDeviceNameInUse(String::from("tap_name")),
        );
        check_error_response(vmm_resp, StatusCode::BadRequest);

        // Tests for MicrovmStart Errors.
        // RegisterBlockDevice, RegisterNetDevice, and LegacyIOBus cannot be tested because the
        // device manager is a private module in the vmm crate.
        // ConfigureVm, Vcpu and VcpuConfigure cannot be tested because vstate is a private module
        // in the vmm crate.
        let vmm_resp =
            VmmActionError::StartMicrovm(ErrorKind::User, StartMicrovmError::MicroVMAlreadyRunning);
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp =
            VmmActionError::StartMicrovm(ErrorKind::User, StartMicrovmError::MissingKernelConfig);
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp = VmmActionError::StartMicrovm(
            ErrorKind::Internal,
            StartMicrovmError::GuestMemory(GuestMemoryError::MemoryNotInitialized),
        );
        check_error_response(vmm_resp, StatusCode::InternalServerError);
        let vmm_resp = VmmActionError::StartMicrovm(
            ErrorKind::Internal,
            StartMicrovmError::KernelCmdline(String::from("dummy error.")),
        );
        check_error_response(vmm_resp, StatusCode::InternalServerError);
        let vmm_resp = VmmActionError::StartMicrovm(
            ErrorKind::Internal,
            StartMicrovmError::CreateBlockDevice(io::Error::from_raw_os_error(22)),
        );
        check_error_response(vmm_resp, StatusCode::InternalServerError);
        let vmm_resp = VmmActionError::StartMicrovm(
            ErrorKind::User,
            StartMicrovmError::OpenBlockDevice(io::Error::from_raw_os_error(22)),
        );
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp = VmmActionError::StartMicrovm(
            ErrorKind::Internal,
            StartMicrovmError::NetDeviceNotConfigured,
        );
        check_error_response(vmm_resp, StatusCode::InternalServerError);
        let vmm_resp = VmmActionError::StartMicrovm(
            ErrorKind::Internal,
            StartMicrovmError::CreateNetDevice(VirtioNetError::TapOpen(TapError::OpenTun(
                io::Error::from_raw_os_error(22),
            ))),
        );
        check_error_response(vmm_resp, StatusCode::InternalServerError);
        let vmm_resp = VmmActionError::StartMicrovm(
            ErrorKind::Internal,
            StartMicrovmError::DeviceVmRequest(io::Error::from_raw_os_error(22)),
        );
        check_error_response(vmm_resp, StatusCode::InternalServerError);
        #[cfg(target_arch = "x86_64")]
        let vmm_resp = VmmActionError::StartMicrovm(
            ErrorKind::Internal,
            StartMicrovmError::ConfigureSystem(arch::Error::X86_64Setup(
                arch::x86_64::Error::ZeroPagePastRamEnd,
            )),
        );
        check_error_response(vmm_resp, StatusCode::InternalServerError);
        let vmm_resp = VmmActionError::StartMicrovm(
            ErrorKind::User,
            StartMicrovmError::Loader(kernel::loader::Error::BigEndianElfOnLittle),
        );
        check_error_response(vmm_resp, StatusCode::BadRequest);
        let vmm_resp =
            VmmActionError::StartMicrovm(ErrorKind::Internal, StartMicrovmError::EventFd);
        check_error_response(vmm_resp, StatusCode::InternalServerError);
        let vmm_resp =
            VmmActionError::StartMicrovm(ErrorKind::Internal, StartMicrovmError::RegisterEvent);
        check_error_response(vmm_resp, StatusCode::InternalServerError);
        let vmm_resp = VmmActionError::StartMicrovm(
            ErrorKind::Internal,
            StartMicrovmError::VcpuSpawn(io::Error::from_raw_os_error(11)),
        );
        check_error_response(vmm_resp, StatusCode::InternalServerError);
    }
}
