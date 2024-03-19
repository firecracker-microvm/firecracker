// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;

const MOCK_KERNEL_PATH: &str = "src/utils/mock_kernel/kernel.bin";

// Kernel header for aarch64 that comes from the kernel doc Documentation/arm64/booting.txt.
#[derive(Default)]
#[repr(C, packed)]
struct KernelHeader {
    code0: u32,       // Executable code
    code1: u32,       // Executable code
    text_offset: u64, // Image load offset,
    image_size: u64,  // Effective Image size, little endian
    flags: u64,       // kernel flags, little endian
    res2: u64,        // reserved
    res3: u64,        // reserved
    res4: u64,        // reserved
    magic: u32,       // Magic number, little endian, "ARM\x64"
    res5: u32,        // reserved (used for PE COFF offset)
}

fn main() {
    if cfg!(target_arch = "x86_64") {
        println!("cargo:rerun-if-changed=src/utils/mock_kernel/main.c");
        let status = std::process::Command::new("gcc")
            .args([
                // Do not use the standard system startup files or libraries when linking.
                "-nostdlib",
                // Prevents linking with the shared libraries.
                "-static",
                // Do not generate unwind tables.
                "-fno-asynchronous-unwind-tables",
                // Remove all symbol table and relocation information.
                "-s",
                "-o",
                MOCK_KERNEL_PATH,
                "src/utils/mock_kernel/main.c",
            ])
            .status()
            .expect("Failed to execute gcc command");
        if !status.success() {
            panic!("Failed to compile mock kernel");
        }
    } else if cfg!(target_arch = "aarch64") {
        let header = KernelHeader {
            magic: 0x644D5241,
            ..std::default::Default::default()
        };
        // SAFETY: This is safe as long as `header` is valid as `KernelHeader`.
        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                (&header as *const KernelHeader).cast::<u8>(),
                std::mem::size_of::<KernelHeader>(),
            )
        };

        let mut file = std::fs::File::create(MOCK_KERNEL_PATH).expect("Failed to create a file");
        file.write_all(header_bytes)
            .expect("Failed to write kernel header to a file");
    } else {
        panic!("Unsupported arch");
    }
}
