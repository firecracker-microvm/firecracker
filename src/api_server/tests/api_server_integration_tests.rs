// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod api_cpu_configuration_integ_tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::mpsc::channel;
    use std::thread;

    use api_server::ApiServer;
    use cpuid::{Cpuid, RawCpuid};
    use guest_config::CustomCpuConfiguration;
    use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
    use kvm_ioctls::Kvm;
    use logger::ProcessTimeReporter;
    use utils::eventfd::EventFd;
    use utils::tempfile::TempFile;
    use vmm::seccomp_filters::{get_filters, SeccompConfig};

    const HTTP_OK_RESPONSE: &str = "HTTP/1.1 200";

    #[cfg(target_arch = "x86_64")]
    #[cfg(target_os = "linux")]
    #[test]
    fn test_put_cpu_config() {
        let cpu_config = supported_cpu_config();

        let mut tmp_socket = TempFile::new().unwrap();
        tmp_socket.remove().unwrap();
        let path_to_socket = tmp_socket.as_path().to_str().unwrap().to_owned();
        let api_thread_path_to_socket = path_to_socket.clone();

        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (_to_api, vmm_response_receiver) = channel();
        let seccomp_filters = get_filters(SeccompConfig::Advanced).unwrap();
        let (socket_ready_sender, socket_ready_receiver) = channel();

        let (cpu_config_api_request, api_payload_size) =
            build_http_put_cpu_config_request(cpu_config);
        let mut api_server = ApiServer::new(api_request_sender, vmm_response_receiver, to_vmm_fd);
        thread::Builder::new()
            .name("fc_api_integ_test".to_owned())
            .spawn(move || {
                api_server
                    .bind_and_run(
                        &PathBuf::from(api_thread_path_to_socket),
                        ProcessTimeReporter::new(Some(1), Some(1), Some(1)),
                        seccomp_filters.get("api").unwrap(),
                        api_payload_size,
                        socket_ready_sender,
                    )
                    .unwrap();
            })
            .unwrap();

        // Wait for the server to be available for requests
        socket_ready_receiver.recv().unwrap();
        let mut sock = UnixStream::connect(PathBuf::from(path_to_socket)).unwrap();

        // Send PUT /cpu-config request.
        assert!(sock.write_all(cpu_config_api_request.as_slice()).is_ok());
        let mut buf = [0; 265];
        assert!(sock.read(&mut buf).unwrap() > 0);
        let server_response = String::from_utf8_lossy(&buf);
        assert!(
            &server_response.to_string().contains(HTTP_OK_RESPONSE),
            "Successful response (200 OK) expected from API server but received: \n\r{}",
            server_response.to_string(),
        );
    }

    fn build_http_put_cpu_config_request(cpu_config: CustomCpuConfiguration) -> (Vec<u8>, usize) {
        let cpu_config_json_result = serde_json::to_string(&cpu_config);
        assert!(
            cpu_config_json_result.is_ok(),
            "Error serializing CustomCpuConfiguration"
        );

        let cpu_config_json = cpu_config_json_result.unwrap();
        // let cpu_config_json = "{\"base_arch_config\":{\"Amd\":{\"cpuid_tree\":{\"{\\\"leaf\\\":0,\\\"subleaf\\\":0}\":{\"flags\":0,\"result\":{\"eax\":16,\"ebx\":1752462657,\"ecx\":1145913699,\"edx\":1769238117}}}}}}";

        let api_payload_size = cpu_config_json.len() as usize;
        (
            format!(
                "PUT /cpu-config HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: \
                 {}\r\n\r\n{}\r\n",
                api_payload_size, cpu_config_json,
            )
            .into_bytes(),
            api_payload_size,
        )
    }

    fn supported_cpu_config() -> CustomCpuConfiguration {
        let kvm_result = Kvm::new();
        assert!(kvm_result.is_ok(), "Unable to access KVM");

        // Create descriptor KVM resource's file descriptor
        let vm_fd_result = kvm_result.as_ref().unwrap().create_vm();
        assert!(vm_fd_result.is_ok(), "{}", vm_fd_result.unwrap_err());

        let kvm_cpuid_result = kvm_result
            .unwrap()
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES);
        assert!(
            kvm_cpuid_result.is_ok(),
            "{}",
            kvm_cpuid_result.unwrap_err()
        );
        let kvm_cpuid = kvm_cpuid_result.unwrap();
        let raw_cpuid = RawCpuid::from(kvm_cpuid);
        let cpuid_result = Cpuid::try_from(raw_cpuid);
        assert!(cpuid_result.is_ok(), "{}", cpuid_result.unwrap_err());
        CustomCpuConfiguration {
            base_arch_config: cpuid_result.unwrap(),
        }
    }
}
