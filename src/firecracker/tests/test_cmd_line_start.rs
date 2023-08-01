// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::process::{Command, Stdio};
use tokio::sync::OnceCell;

use utils::tempfile::TempFile;

const BINARY: &str = env!("CARGO_BIN_EXE_firecracker");
#[cfg(target_arch = "x86_64")]
const ARCH: &str = "x86_64";
#[cfg(target_arch = "aarch64")]
const ARCH: &str = "aarch64";

use std::time::Duration;

/// Returns reference to temporary file with kernel image.
async fn kernel() -> &'static TempFile {
    static KERNEL: OnceCell<TempFile> = OnceCell::const_new();
    async fn init() -> TempFile {
        let file = TempFile::new().unwrap();
        assert_eq!(file.as_file().metadata().unwrap().len(), 0);

        let url = format!(
            "https://s3.amazonaws.com/spec.ccfc.min/ci-artifacts/kernels/{ARCH}/vmlinux-5.10.bin"
        );
        let bytes = reqwest::get(url).await.unwrap().bytes().await.unwrap();
        file.as_file().write_all(&bytes).unwrap();
        file
    }
    KERNEL.get_or_init(init).await
}
/// Returns reference to temporary file with rootfs.
async fn rootfs() -> &'static TempFile {
    static ROOTFS: OnceCell<TempFile> = OnceCell::const_new();
    async fn init() -> TempFile {
        let file = TempFile::new().unwrap();
        assert_eq!(file.as_file().metadata().unwrap().len(), 0);

        // Increase timeout from default of 30s to 60s.
        let url = format!(
            "https://s3.amazonaws.com/spec.ccfc.min/ci-artifacts/disks/{ARCH}/ubuntu-18.04.ext4"
        );
        let client = reqwest::Client::new();
        let bytes = client
            .get(url)
            .timeout(Duration::from_secs(120))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        file.as_file().write_all(&bytes).unwrap();
        file
    }
    ROOTFS.get_or_init(init).await
}

#[test]
fn test_start_with_metadata_limit() {
    // Create json file with metadata config.
    let metadata = r#"{
    "latest": {
        "meta-data": "Lorem ipsum dolor sit amet, consectetur adipiscing elit",
        "user-data": "userdata 1 2 3 4"
    },
    "2016-09-02": {
        "meta-data": "Lorem ipsum dolor sit amet"
    },
    "2019-08-01": {
        "some-data": {
            "field1": "val1",
            "field2": [1,2,3,4]
        }
    }  
}"#;
    let metadata_file = TempFile::new().unwrap();
    metadata_file
        .as_file()
        .write_all(metadata.as_bytes())
        .unwrap();
    let metadata_path = metadata_file.as_path().as_os_str().to_str().unwrap();

    // Start firecracker process pointing to this file as the API socket.
    let socket_path = format!("/tmp/{}", uuid::Uuid::new_v4());
    let output = std::process::Command::new(BINARY)
        .args([
            "--api-sock",
            &socket_path,
            "--mmds-size-limit",
            "30",
            "--metadata",
            metadata_path,
        ])
        .output()
        .unwrap();

    // Assert the firecracker process exited with expected results.
    assert_eq!(output.status.code().unwrap(), 1);
    assert_eq!(output.stdout, b"");
    let expected_stderr =
        b"Error: RunWithApi(BuildMicrovmFromRequests(PopulateMmds(DataStoreLimitExceeded)))\n";
    assert_eq!(output.stderr, expected_stderr);
}

#[test]
fn test_start_with_metadata_default_limit() {
    // Create json file with metadata config.
    let metadata = r#"{
    "latest": {
        "meta-data": "Lorem ipsum dolor sit amet, consectetur adipiscing elit",
        "user-data": "userdata 1 2 3 4"
    },
    "2016-09-02": {
        "meta-data": "Lorem ipsum dolor sit amet"
    },
    "2019-08-01": {
        "some-data": {
            "field1": "val1",
            "field2": [1,2,3,4]
        }
    }  
}"#;
    let metadata_file = TempFile::new().unwrap();
    metadata_file
        .as_file()
        .write_all(metadata.as_bytes())
        .unwrap();
    let metadata_path = metadata_file.as_path().as_os_str().to_str().unwrap();

    // Start firecracker process pointing to this file as the API socket.
    let socket_path = format!("/tmp/{}", uuid::Uuid::new_v4());
    let output = std::process::Command::new(BINARY)
        .args([
            "--api-sock",
            &socket_path,
            "--http-api-max-payload-size",
            "30",
            "--metadata",
            metadata_path,
        ])
        .output()
        .unwrap();

    // Assert the firecracker process exited with expected results.
    assert_eq!(output.status.code().unwrap(), 1);
    assert_eq!(output.stdout, b"");
    let expected_stderr =
        b"Error: RunWithApi(BuildMicrovmFromRequests(PopulateMmds(DataStoreLimitExceeded)))\n";
    assert_eq!(output.stderr, expected_stderr);
}

#[test]
fn test_start_with_invalid_metadata() {
    // Create json file with metadata config.
    let metadata = r#"{
"latest": {
    "meta-data": "Lorem ipsum dolor sit amet, consectetur adipiscing elit",
    "user-data": "userdata 1 2 3 4""#;
    let metadata_file = TempFile::new().unwrap();
    metadata_file
        .as_file()
        .write_all(metadata.as_bytes())
        .unwrap();
    let metadata_path = metadata_file.as_path().as_os_str().to_str().unwrap();

    // Start firecracker process pointing to this file as the API socket.
    let socket_path = format!("/tmp/{}", uuid::Uuid::new_v4());
    let output = std::process::Command::new(BINARY)
        .args(["--api-sock", &socket_path, "--metadata", metadata_path])
        .output()
        .unwrap();

    // Assert the firecracker process exited with expected results.
    assert_eq!(output.status.code().unwrap(), 1);
    assert_eq!(output.stdout, b"");
    let expected_stderr = b"Error: RunWithApi(BuildMicrovmFromRequests(MmdsData(Error(\"EOF while parsing an object\", line: 4, column: 35))))\n";
    assert_eq!(output.stderr, expected_stderr);
}

// Test microvm start when the `machine_config` is invalid.
#[tokio::test]
async fn test_config_bad_machine_config_missing_vcpu_count() {
    let kernel_str = kernel().await.as_path().as_os_str().to_str().unwrap();
    let rootfs_str = rootfs().await.as_path().as_os_str().to_str().unwrap();

    // Create temp json file with bad config.
    let config = format!(
        "{{
    \"boot-source\": {{
        \"kernel_image_path\": \"{kernel_str}\",
        \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off\"
    }},
    \"drives\": [
        {{
        \"drive_id\": \"rootfs\",
        \"path_on_host\": \"{rootfs_str}\",
        \"is_root_device\": true,
        \"is_read_only\": false
        }}
    ],
    \"machine-config\": {{
        \"mem_size_mib\": 1024,
        \"smt\": false,
        \"track_dirty_pages\": false
    }}
}}"
    );
    let file = TempFile::new().unwrap();
    file.as_file().write_all(config.as_bytes()).unwrap();

    // Run firecracker with config file
    let path = file.as_path().as_os_str().to_str().unwrap();
    let output = Command::new(BINARY)
        .args(["--no-api", "--config-file", path])
        .output()
        .unwrap();

    // Assert the firecracker process exited with expected results.
    assert_eq!(output.status.code().unwrap(), 1);
    assert_eq!(output.stdout, b"");
    let expected_stderr = format!(
        "Error: RunWithoutApiError(BuildMicroVMFromJson(ParseFromJson(InvalidJson(Error(\"missing \
         field `vcpu_count`\", line: 18, column: 5)))))\n"
    );
    assert_eq!(output.stderr, expected_stderr.as_bytes());
}

// Test microvm start when the `machine_config` is invalid.
#[tokio::test]
async fn test_config_bad_machine_config_missing_mem_size_mib() {
    let kernel_str = kernel().await.as_path().as_os_str().to_str().unwrap();
    let rootfs_str = rootfs().await.as_path().as_os_str().to_str().unwrap();

    // Create temp json file with bad config.
    let config = format!(
        "{{
    \"boot-source\": {{
        \"kernel_image_path\": \"{kernel_str}\",
        \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off\"
    }},
    \"drives\": [
        {{
        \"drive_id\": \"rootfs\",
        \"path_on_host\": \"{rootfs_str}\",
        \"is_root_device\": true,
        \"is_read_only\": false
        }}
    ],
    \"machine-config\": {{
        \"vcpu_count\": 2,
        \"smt\": false,
        \"track_dirty_pages\": false
    }}
}}"
    );
    let file = TempFile::new().unwrap();
    file.as_file().write_all(config.as_bytes()).unwrap();

    // Run firecracker with config file
    let path = file.as_path().as_os_str().to_str().unwrap();
    let output = Command::new(BINARY)
        .args(["--no-api", "--config-file", path])
        .output()
        .unwrap();

    // Assert the firecracker process exited with expected results.
    assert_eq!(output.status.code().unwrap(), 1);
    assert_eq!(output.stdout, b"");
    let expected_stderr = format!(
        "Error: RunWithoutApiError(BuildMicroVMFromJson(ParseFromJson(InvalidJson(Error(\"missing \
         field `mem_size_mib`\", line: 18, column: 5)))))\n"
    );
    assert_eq!(output.stderr, expected_stderr.as_bytes());
}

// Test microvm start with optional `machine_config` parameters.
#[tokio::test]
async fn test_config_machine_config_params_cpu_template_c3() {
    let kernel_str = kernel().await.as_path().as_os_str().to_str().unwrap();
    let rootfs_str = rootfs().await.as_path().as_os_str().to_str().unwrap();

    // Writes configuration to temporary file.
    let config = format!(
        "{{
    \"boot-source\": {{
        \"kernel_image_path\": \"{kernel_str}\",
        \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off\"
    }},
    \"drives\": [
        {{
        \"drive_id\": \"rootfs\",
        \"path_on_host\": \"{rootfs_str}\",
        \"is_root_device\": true,
        \"is_read_only\": false
        }}
    ],
    \"machine-config\": {{
        \"vcpu_count\": 2,
        \"mem_size_mib\": 1024,
        \"cpu_template\": \"C3\"
    }}
}}"
    );
    let file = TempFile::new().unwrap();
    file.as_file().write_all(config.as_bytes()).unwrap();

    // Run firecracker with config file
    let path = file.as_path().as_os_str().to_str().unwrap();

    #[cfg(target_arch = "x86_64")]
    let mut process = Command::new(BINARY)
        .args(["--no-api", "--config-file", path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    #[cfg(target_arch = "aarch64")]
    let process = Command::new(BINARY)
        .args(["--no-api", "--config-file", path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // The configuration used here is only valid on intel, thus if the host is intel we expect
    // success otherwise we expect failure.

    #[cfg(target_arch = "x86_64")]
    {
        let leaf = unsafe { std::arch::x86_64::__cpuid(0) };
        let vendor = unsafe { std::mem::transmute::<_, [u8; 12]>([leaf.ebx, leaf.edx, leaf.ecx]) };
        match &vendor {
            b"GenuineIntel" => {
                // We sleep to allow firecracker process to start microvm
                // TODO Avoid this arbitrary sleep
                std::thread::sleep(Duration::from_secs(10));
                process.kill().unwrap();
                let output = process.wait_with_output().unwrap();

                // Assert microvm was successfully booted.
                let stdout_str = std::str::from_utf8(&output.stdout).unwrap();
                let expected_stdout = "Ubuntu 18.04.1 LTS 7e47bb8f2f0a ttyS0";
                assert!(
                    stdout_str.contains(expected_stdout),
                    "{stdout_str}\ndoes not contain:\n{expected_stdout}\n"
                );
            }
            b"AuthenticAMD" => {
                let output = process.wait_with_output().unwrap();

                assert_eq!(output.status.code().unwrap(), 1);
                assert!(output.stdout.is_empty());

                let expected_stderr = b"Error: RunWithoutApiError(BuildMicroVMFromJson(StartMicroVM(GetCpuTemplate(CpuVendorMismatched))))\n";
                let n = output.stderr.len() - expected_stderr.len();
                assert_eq!(
                    &output.stderr[n..],
                    expected_stderr,
                    "{:?} != {:?}",
                    std::str::from_utf8(&output.stderr),
                    std::str::from_utf8(expected_stderr),
                );
            }
            _ => unreachable!(),
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let output = process.wait_with_output().unwrap();

        assert_eq!(output.status.code().unwrap(), 1);
        assert!(output.stdout.is_empty());

        let expected_stderr = b"Error: RunWithoutApiError(BuildMicroVMFromJson(ParseFromJson(InvalidJson(Error(\"unknown variant `C3`, expected one of `Empty0`, `Empty1`, `V1N1`, `None`\", line: 17, column: 28)))))\n";
        assert_eq!(
            output.stderr,
            expected_stderr,
            "{:?} != {:?}",
            std::str::from_utf8(&output.stderr),
            std::str::from_utf8(expected_stderr),
        );
    }
}

// Test microvm start with optional `machine_config` parameters.
#[tokio::test]
async fn test_config_machine_config_params_smt_true() {
    let kernel_str = kernel().await.as_path().as_os_str().to_str().unwrap();
    let rootfs_str = rootfs().await.as_path().as_os_str().to_str().unwrap();

    // Writes configuration to temporary file.
    let config = format!(
        "{{
    \"boot-source\": {{
        \"kernel_image_path\": \"{kernel_str}\",
        \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off\"
    }},
    \"drives\": [
        {{
        \"drive_id\": \"rootfs\",
        \"path_on_host\": \"{rootfs_str}\",
        \"is_root_device\": true,
        \"is_read_only\": false
        }}
    ],
    \"machine-config\": {{
        \"vcpu_count\": 2,
        \"mem_size_mib\": 1024,
        \"smt\": true
    }}
}}"
    );
    let file = TempFile::new().unwrap();
    file.as_file().write_all(config.as_bytes()).unwrap();

    // Run firecracker with config file
    let path = file.as_path().as_os_str().to_str().unwrap();
    let mut process = Command::new(BINARY)
        .args(["--no-api", "--config-file", path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // The configuration used here is only valid x86_64.
    if cfg!(target_arch = "x86_64") {
        // We sleep to allow firecracker process to start microvm
        // TODO Avoid this arbitrary sleep
        std::thread::sleep(Duration::from_secs(10));
        process.kill().unwrap();
        let output = process.wait_with_output().unwrap();

        // Assert microvm was successfully booted.
        let stdout_str = std::str::from_utf8(&output.stdout).unwrap();
        let expected_stdout = "Ubuntu 18.04.1 LTS 7e47bb8f2f0a ttyS0";
        assert!(
            stdout_str.contains(expected_stdout),
            "{stdout_str}\ndoes not contain:\n{expected_stdout}\n"
        );
    } else {
        let output = process.wait_with_output().unwrap();

        assert_eq!(output.status.code().unwrap(), 1);
        assert!(output.stdout.is_empty());

        let expected_stderr = b"Error: RunWithoutApiError(BuildMicroVMFromJson(ParseFromJson(InvalidJson(Error(\"invalid value: smt, expected Enabling simultaneous multithreading is not supported on aarch64\", line: 18, column: 5)))))\n";
        assert_eq!(
            output.stderr,
            expected_stderr,
            "{:?} != {:?}",
            std::str::from_utf8(&output.stderr),
            std::str::from_utf8(expected_stderr),
        );
    }
}
