// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use http::uri::Uri as HyperUri;
use http::Extensions;
use hyper::header::HeaderMap;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Body, Method, StatusCode, Version};
use hyperlocal::{UnixClientExt, Uri};
use std::io::Read;
use std::io::Write;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::OnceCell;
use utils::tempfile::TempFile;

const BINARY: &str = env!("CARGO_BIN_EXE_firecracker");
#[cfg(target_arch = "x86_64")]
const ARCH: &str = "x86_64";
#[cfg(target_arch = "aarch64")]
const ARCH: &str = "aarch64";

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

// Test error scenario when PF handler has not yet called bind on socket.
//
// 1. Obtain a microVM snapshot (start firecracker -> start microVM -> pause microVM -> snapshot microVM -> exit firecracker)
// 2. Start a page fault handler on the obtain snapshot files.
#[tokio::test]
async fn test_unbinded_socket() {
    // Gets the kernel and rootfs
    let kernel_str = kernel().await.as_path().as_os_str().to_str().unwrap();
    let rootfs_str = rootfs().await.as_path().as_os_str().to_str().unwrap();

    // Start firecracker process with API socket.
    let socket_path = format!("/tmp/{}", uuid::Uuid::new_v4());
    let mut firecracker_snapshot_process = std::process::Command::new(BINARY)
        .args(["--api-sock", &socket_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Sleep long enough for the firecracker process to start and create the API unix socket.
    // TODO Remove this.
    std::thread::sleep(Duration::from_secs(4));

    // Set http client
    let client = hyper::Client::unix();

    // TODO Add assertions on the response bodies and extensions e.g.
    // `assert_eq!(response.body(),&Body::empty())` and
    // `assert_eq!(response.extensions(), Extensions::new())`.

    // Set boot source
    {
        let body = serde_json::json!({
            "kernel_image_path": kernel_str,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
        });
        let uri = HyperUri::from(Uri::new(&socket_path, "/boot-source"));
        let request = hyper::Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .body(hyper::Body::from(body.to_string()))
            .unwrap();
        let response = client.request(request).await.unwrap();
        assert_eq!(
            response.headers(),
            &HeaderMap::from_iter([
                (
                    HeaderName::from_static("server"),
                    HeaderValue::from_static("Firecracker API")
                ),
                (
                    HeaderName::from_static("connection"),
                    HeaderValue::from_static("keep-alive")
                )
            ])
        );
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.version(), Version::HTTP_11);
    }

    // Set rootfs
    {
        let body = serde_json::json!({
            "drive_id": "rootfs",
            "path_on_host": rootfs_str,
            "is_root_device": true,
            "is_read_only": false
        });
        let uri = HyperUri::from(Uri::new(&socket_path, "/drives/rootfs"));
        let request = hyper::Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .body(hyper::Body::from(body.to_string()))
            .unwrap();
        let response = client.request(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = hyper::body::to_bytes(body).await.unwrap();
        let temp = std::str::from_utf8(&bytes);
        println!("temp: {:?}", temp);
        // assert_eq!(, serde_json::json!({ "temp": "temp"}).to_string().as_bytes());
        assert_eq!(
            parts.headers,
            HeaderMap::from_iter([
                (
                    HeaderName::from_static("server"),
                    HeaderValue::from_static("Firecracker API")
                ),
                (
                    HeaderName::from_static("connection"),
                    HeaderValue::from_static("keep-alive")
                )
            ])
        );
        assert_eq!(parts.status, StatusCode::NO_CONTENT);
        assert_eq!(parts.version, Version::HTTP_11);
    }

    // Start VM
    {
        let body = serde_json::json!({
            "action_type": "InstanceStart",
        });
        let uri = HyperUri::from(Uri::new(&socket_path, "/actions"));
        let request = hyper::Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .body(hyper::Body::from(body.to_string()))
            .unwrap();
        let response = client.request(request).await.unwrap();
        assert_eq!(
            response.headers(),
            &HeaderMap::from_iter([
                (
                    HeaderName::from_static("server"),
                    HeaderValue::from_static("Firecracker API")
                ),
                (
                    HeaderName::from_static("connection"),
                    HeaderValue::from_static("keep-alive")
                )
            ])
        );
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.version(), Version::HTTP_11);
    }

    // Pause VM
    {
        let body = serde_json::json!({
            "state": "Paused",
        });
        let uri = HyperUri::from(Uri::new(&socket_path, "/vm"));
        let request = hyper::Request::builder()
            .method(Method::PATCH)
            .uri(uri)
            .body(hyper::Body::from(body.to_string()))
            .unwrap();
        let response = client.request(request).await.unwrap();
        assert_eq!(
            response.headers(),
            &HeaderMap::from_iter([
                (
                    HeaderName::from_static("server"),
                    HeaderValue::from_static("Firecracker API")
                ),
                (
                    HeaderName::from_static("connection"),
                    HeaderValue::from_static("keep-alive")
                )
            ])
        );
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.version(), Version::HTTP_11);
    }

    // Snapshot VM
    let (mem_file_path, snapshot_path) = {
        let mem_file_path = format!("/tmp/{}", uuid::Uuid::new_v4());
        let snapshot_path = format!("/tmp/{}", uuid::Uuid::new_v4());
        let body = serde_json::json!({
            "mem_file_path": mem_file_path,
            "snapshot_path": snapshot_path,
            "snapshot_type": "Full",
            "version": "1.4.0"
        });
        let uri = HyperUri::from(Uri::new(&socket_path, "/snapshot/create"));
        let request = hyper::Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .body(hyper::Body::from(body.to_string()))
            .unwrap();
        let response = client.request(request).await.unwrap();
        assert_eq!(
            response.headers(),
            &HeaderMap::from_iter([
                (
                    HeaderName::from_static("server"),
                    HeaderValue::from_static("Firecracker API")
                ),
                (
                    HeaderName::from_static("connection"),
                    HeaderValue::from_static("keep-alive")
                )
            ])
        );
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.version(), Version::HTTP_11);
        (mem_file_path, snapshot_path)
    };

    // Exit firecracker process
    firecracker_snapshot_process.kill().unwrap();
    let _output = firecracker_snapshot_process.wait_with_output().unwrap();

    // TODO Assert stdout and stderr are expected values.

    // Start new firecracker process
    let socket_path = format!("/tmp/{}", uuid::Uuid::new_v4());
    let mut firecracker_restore_process = std::process::Command::new(BINARY)
        .args(["--api-sock", &socket_path])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    let uffd_socket = TempFile::new().unwrap();
    let uffd_socket_path = uffd_socket.as_path().as_os_str().to_str().unwrap();

    // Sleep long enough for the firecracker process to start and create the API unix socket.
    // TODO Remove this.
    std::thread::sleep(Duration::from_secs(4));

    // Load snapshot
    {
        let body = serde_json::json!({
            "enable_diff_snapshots": false,
            "mem_backend": {
              "backend_type": "Uffd",
              "backend_path": uffd_socket_path
            },
            "snapshot_path": snapshot_path,
            "resume_vm": false
        });
        let uri = HyperUri::from(Uri::new(&socket_path, "/snapshot/load"));
        let request = hyper::Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .body(hyper::Body::from(body.to_string()))
            .unwrap();

        dbg!();
        // let mut buffer = [u8::default(); 2048];
        // firecracker_restore_process
        //     .stdout
        //     .as_mut()
        //     .unwrap()
        //     .read(&mut buffer)
        //     .unwrap();
        // println!("stdout_buffer: {:?}", std::str::from_utf8(&buffer));
        dbg!();
        // buffer = [u8::default(); 2048];
        // firecracker_restore_process
        //     .stderr
        //     .as_mut()
        //     .unwrap()
        //     .read(&mut buffer)
        //     .unwrap();
        // println!("stderr_buffer: {:?}", std::str::from_utf8(&buffer));
        dbg!();
        let temp = client.request(request).await;
        std::thread::sleep(Duration::from_secs(4));

        dbg!();
        // buffer = [u8::default(); 2048];
        // firecracker_restore_process
        //     .stdout
        //     .as_mut()
        //     .unwrap()
        //     .read(&mut buffer)
        //     .unwrap();
        // println!("stdout_buffer: {:?}", std::str::from_utf8(&buffer));
        dbg!();
        // buffer = [u8::default(); 2048];
        // firecracker_restore_process
        //     .stderr
        //     .as_mut()
        //     .unwrap()
        //     .read(&mut buffer)
        //     .unwrap();
        // println!("stderr_buffer: {:?}", std::str::from_utf8(&buffer));

        dbg!();
        let response = temp.unwrap();

        let (parts, body) = response.into_parts();
        let bytes = hyper::body::to_bytes(body).await.unwrap();
        let temp = std::str::from_utf8(&bytes);
        println!("temp: {:?}", temp);
        assert_eq!(
            parts.headers,
            HeaderMap::from_iter([
                (
                    HeaderName::from_static("server"),
                    HeaderValue::from_static("Firecracker API")
                ),
                (
                    HeaderName::from_static("connection"),
                    HeaderValue::from_static("keep-alive")
                )
            ])
        );
        assert_eq!(parts.status, StatusCode::NO_CONTENT);
        assert_eq!(parts.version, Version::HTTP_11);
        // TODO Bad response
    }
}
