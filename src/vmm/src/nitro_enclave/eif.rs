// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! EIF (Enclave Image Format) builder.
//!
//! Sizes an EIF image from kernel, initrd, and command line, then writes it
//! directly into enclave memory in the format expected by Nitro Enclaves.
//!
//! The EIF format uses big-endian byte order throughout, matching the
//! `aws-nitro-enclaves-image-format` crate.
//!
//! TODO: Generalize <https://github.com/aws/aws-nitro-enclaves-image-format>
//! to accept `impl Write` (currently hardcoded to `&mut File`) and switch to
//! the upstream crate. Until then we serialize into the destination slice here.

use std::fs::File;
use std::io::{Read, Seek};
use std::mem::size_of;
use std::os::unix::fs::FileExt;

use crc32fast::Hasher as Crc32Hasher;
use zerocopy::byteorder::big_endian;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::utils::u64_to_usize;

/// EIF magic number.
const EIF_MAGIC: [u8; 4] = *b".eif";

/// EIF header version.
const EIF_HDR_VERSION: u16 = 4;

/// Section types (matching aws-nitro-enclaves-image-format).
const EIF_SECTION_KERNEL: u16 = 1;
const EIF_SECTION_CMDLINE: u16 = 2;
const EIF_SECTION_RAMDISK: u16 = 3;
const EIF_SECTION_METADATA: u16 = 5;

/// EIF header flag: PCIE device model (bit 6).
pub const EIF_HDR_FLAG_PCIE: u16 = 1 << 6;
/// EIF header flag: rigid vsock shape (bit 7).
pub const EIF_HDR_FLAG_PCIE_VSOCK: u16 = 1 << 7;
/// EIF header flag: hotplug support (bit 8).
pub const EIF_HDR_FLAG_PCIE_HOTPLUG: u16 = 1 << 8;
/// EIF header flag: permissive virtio (bit 9).
pub const EIF_HDR_FLAG_PCIE_VIRTIO: u16 = 1 << 9;

/// Architecture flag for the current platform (matching aws-nitro-enclaves-image-format).
#[cfg(target_arch = "aarch64")]
const EIF_ARCH_FLAG: u16 = 1;
#[cfg(target_arch = "x86_64")]
const EIF_ARCH_FLAG: u16 = 0;

/// Maximum number of sections in the fixed-size header arrays.
const MAX_NUM_SECTIONS: usize = 32;

/// EIF file header (big-endian on disk).
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct EifHeader {
    magic: [u8; 4],
    version: big_endian::U16,
    flags: big_endian::U16,
    default_mem: big_endian::U64,
    default_cpus: big_endian::U64,
    reserved: big_endian::U16,
    num_sections: big_endian::U16,
    section_offsets: [big_endian::U64; MAX_NUM_SECTIONS],
    section_sizes: [big_endian::U64; MAX_NUM_SECTIONS],
    unused: big_endian::U32,
    eif_crc32: big_endian::U32,
}

impl EifHeader {
    /// Lay out the sections and return the header with the total image length.
    ///
    /// Fails with [`EifError::SizeOverflow`] if the image length overflows `u64`. The lengths come
    /// from file metadata, so a large sparse kernel or initrd could otherwise wrap the layout.
    fn new(
        kernel_len: u64,
        initrd_len: Option<u64>,
        cmdline_len: u64,
        default_mem: u64,
        default_cpus: u64,
        pcie_flags: u16,
    ) -> Result<(Self, usize), EifError> {
        let mut header = Self {
            magic: EIF_MAGIC,
            version: big_endian::U16::new(EIF_HDR_VERSION),
            flags: big_endian::U16::new(EIF_ARCH_FLAG | pcie_flags),
            default_mem: big_endian::U64::new(default_mem),
            default_cpus: big_endian::U64::new(default_cpus),
            reserved: big_endian::U16::ZERO,
            num_sections: big_endian::U16::ZERO,
            section_offsets: [big_endian::U64::ZERO; MAX_NUM_SECTIONS],
            section_sizes: [big_endian::U64::ZERO; MAX_NUM_SECTIONS],
            unused: big_endian::U32::ZERO,
            eif_crc32: big_endian::U32::ZERO,
        };

        // Each section follows the previous one: a section header, then its data.
        let mut offset = size_of::<Self>() as u64;
        // The hypervisor expects kernel, cmdline, optional ramdisk, then metadata.
        let section_sizes = [
            Some(kernel_len),
            Some(cmdline_len),
            initrd_len,
            Some(EIF_METADATA.len() as u64),
        ];
        let mut num_sections: u16 = 0;
        for size in section_sizes.into_iter().flatten() {
            let index = usize::from(num_sections);
            header.section_offsets[index] = big_endian::U64::new(offset);
            header.section_sizes[index] = big_endian::U64::new(size);
            offset = offset
                .checked_add(size_of::<EifSectionHeader>() as u64)
                .and_then(|offset| offset.checked_add(size))
                .ok_or(EifError::SizeOverflow)?;
            num_sections += 1;
        }
        header.num_sections = big_endian::U16::new(num_sections);
        Ok((header, u64_to_usize(offset)))
    }
}

/// EIF section header (big-endian on disk).
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct EifSectionHeader {
    section_type: big_endian::U16,
    flags: big_endian::U16,
    size: big_endian::U64,
}

impl EifSectionHeader {
    fn new(section_type: u16, size: u64) -> Self {
        Self {
            section_type: big_endian::U16::new(section_type),
            flags: big_endian::U16::ZERO,
            size: big_endian::U64::new(size),
        }
    }
}

const EIF_CRC32_OFFSET: usize = std::mem::offset_of!(EifHeader, eif_crc32);

/// Check whether a file is an EIF by reading the first 4 bytes (magic number).
pub fn is_eif(file: &File) -> bool {
    let mut magic = [0u8; 4];
    file.read_exact_at(&mut magic, 0).is_ok() && magic == EIF_MAGIC
}

/// Input file of an EIF image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, displaydoc::Display)]
pub enum FileKind {
    /// kernel image
    Kernel,
    /// initrd image
    Initrd,
    /// EIF image
    Eif,
}

/// Errors from EIF building.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EifError {
    /// Failed to {op} {kind} {path}: {source}
    Read {
        /// The operation that failed: "stat", "seek", or "read".
        op: &'static str,
        /// Kind of input file.
        kind: FileKind,
        /// Path identifying the already-open descriptor.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Kernel image is empty
    EmptyKernel,
    /// EIF image size overflows
    SizeOverflow,
    /// EIF destination is smaller than the image
    DestinationTooSmall,
}

#[derive(Debug)]
struct InputFile<'a> {
    file: &'a File,
    path: &'a str,
    kind: FileKind,
}

impl InputFile<'_> {
    fn len(&self) -> Result<u64, EifError> {
        self.file
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(|source| EifError::Read {
                op: "stat",
                kind: self.kind,
                path: self.path.to_string(),
                source,
            })
    }

    /// Rewind the file and read exactly `destination.len()` bytes from it.
    ///
    /// Descriptors are rewound first, so a retried `InstanceStart` reuses them.
    /// A payload that shrank after sizing fails with `UnexpectedEof`; one that
    /// grew contributes only the recorded number of bytes.
    fn read_into(&self, destination: &mut [u8]) -> Result<(), EifError> {
        let mut file = self.file;
        file.rewind().map_err(|source| EifError::Read {
            op: "seek",
            kind: self.kind,
            path: self.path.to_string(),
            source,
        })?;
        file.read_exact(destination)
            .map_err(|source| EifError::Read {
                op: "read",
                kind: self.kind,
                path: self.path.to_string(),
                source,
            })
    }
}

/// An EIF whose size is known before any payload is read.
///
/// Borrows the descriptors `BootConfig` already opened, so the bytes
/// [`is_eif`] inspected are the bytes that get loaded, and a retried
/// `InstanceStart` rewinds and reuses the same files.
#[derive(Debug)]
pub struct EifImage<'a> {
    size: usize,
    source: Source<'a>,
}

// One short-lived value per boot; the 548-byte header is not worth boxing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum Source<'a> {
    /// A prebuilt image, copied unchanged.
    Prebuilt(InputFile<'a>),
    /// An image assembled from kernel, optional initrd, and command line.
    Generated {
        header: EifHeader,
        kernel: InputFile<'a>,
        initrd: Option<InputFile<'a>>,
        cmdline: String,
    },
}

impl<'a> EifImage<'a> {
    /// Size a prebuilt EIF from the descriptor [`is_eif`] inspected.
    pub fn prebuilt(file: &'a File, path: &'a str) -> Result<Self, EifError> {
        let input = InputFile {
            file,
            path,
            kind: FileKind::Eif,
        };
        Ok(Self {
            size: u64_to_usize(input.len()?),
            source: Source::Prebuilt(input),
        })
    }

    /// Describe an EIF to assemble from a kernel, optional initrd, and command line.
    ///
    /// Only the file sizes are read here; the payloads are read by [`write`].
    /// `default_mem` and `default_cpus` are written into the big-endian header.
    /// An absent initrd omits the ramdisk section; a present empty initrd retains it.
    ///
    /// [`write`]: EifImage::write
    pub fn new(
        kernel: &'a File,
        kernel_path: &'a str,
        initrd: Option<(&'a File, &'a str)>,
        cmdline: String,
        default_mem: u64,
        default_cpus: u64,
        pcie_flags: u16,
    ) -> Result<Self, EifError> {
        let kernel = InputFile {
            file: kernel,
            path: kernel_path,
            kind: FileKind::Kernel,
        };
        let kernel_len = kernel.len()?;
        if kernel_len == 0 {
            return Err(EifError::EmptyKernel);
        }
        let initrd = initrd.map(|(file, path)| InputFile {
            file,
            path,
            kind: FileKind::Initrd,
        });
        let initrd_len = initrd.as_ref().map(InputFile::len).transpose()?;
        let (header, size) = EifHeader::new(
            kernel_len,
            initrd_len,
            cmdline.len() as u64,
            default_mem,
            default_cpus,
            pcie_flags,
        )?;
        Ok(Self {
            size,
            source: Source::Generated {
                header,
                kernel,
                initrd,
                cmdline,
            },
        })
    }

    /// Total image size in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Write the image into the first `size()` bytes of `destination`.
    pub fn write(&self, destination: &mut [u8]) -> Result<(), EifError> {
        let destination = destination
            .get_mut(..self.size)
            .ok_or(EifError::DestinationTooSmall)?;
        match &self.source {
            Source::Prebuilt(input) => input.read_into(destination),
            Source::Generated {
                header,
                kernel,
                initrd,
                cmdline,
            } => write_generated(header, kernel, initrd.as_ref(), cmdline, destination),
        }
    }
}

/// Serialize an assembled image into a destination of exactly its length.
fn write_generated(
    header: &EifHeader,
    kernel: &InputFile<'_>,
    initrd: Option<&InputFile<'_>>,
    cmdline: &str,
    destination: &mut [u8],
) -> Result<(), EifError> {
    destination[..size_of::<EifHeader>()].copy_from_slice(header.as_bytes());
    kernel.read_into(write_section(destination, header, 0, EIF_SECTION_KERNEL))?;
    write_section(destination, header, 1, EIF_SECTION_CMDLINE).copy_from_slice(cmdline.as_bytes());
    let mut metadata_index = 2;
    if let Some(file) = initrd {
        file.read_into(write_section(destination, header, 2, EIF_SECTION_RAMDISK))?;
        metadata_index = 3;
    }
    write_section(destination, header, metadata_index, EIF_SECTION_METADATA)
        .copy_from_slice(EIF_METADATA.as_bytes());

    // The CRC covers the whole image except its own four-byte field.
    let mut hasher = Crc32Hasher::new();
    hasher.update(&destination[..EIF_CRC32_OFFSET]);
    hasher.update(&destination[EIF_CRC32_OFFSET + 4..]);
    destination[EIF_CRC32_OFFSET..][..4].copy_from_slice(&hasher.finalize().to_be_bytes());
    Ok(())
}

/// Minimal metadata JSON required by the NE hypervisor.
// TODO(enclave): understand if we need to fill this information
const EIF_METADATA: &str = r#"{"ImageName":"firecracker-enclave","ImageVersion":"","BuildMetadata":{"BuildTime":"","BuildTool":"firecracker","BuildToolVersion":"","OperatingSystem":"Linux","KernelVersion":""},"DockerInfo":{},"CustomMetadata":null}"#;

/// Write a section header at its recorded offset and return its payload destination.
///
/// The offsets and sizes are in range: `EifHeader::new` computed them together with the image
/// size, and `destination` is exactly that size.
fn write_section<'a>(
    destination: &'a mut [u8],
    header: &EifHeader,
    index: usize,
    section_type: u16,
) -> &'a mut [u8] {
    let size = header.section_sizes[index].get();
    let offset = u64_to_usize(header.section_offsets[index].get());
    let section = &mut destination[offset..][..size_of::<EifSectionHeader>() + u64_to_usize(size)];
    let (section_header, payload) = section.split_at_mut(size_of::<EifSectionHeader>());
    section_header.copy_from_slice(EifSectionHeader::new(section_type, size).as_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{ErrorKind, SeekFrom, Write};

    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    /// Write `image` into a buffer of exactly its size and return the buffer.
    fn write_image(image: &EifImage) -> Result<Vec<u8>, EifError> {
        let mut eif = vec![0; image.size()];
        image.write(&mut eif)?;
        Ok(eif)
    }

    /// Build an image into memory the way enclave boot does and return its bytes.
    fn build_eif(
        kernel_file: &File,
        initrd_file: Option<&File>,
        cmdline: &str,
        default_mem: u64,
        default_cpus: u64,
        pcie_flags: u16,
    ) -> Result<Vec<u8>, EifError> {
        let image = EifImage::new(
            kernel_file,
            "kernel",
            initrd_file.map(|file| (file, "initrd")),
            cmdline.to_string(),
            default_mem,
            default_cpus,
            pcie_flags,
        )?;
        write_image(&image)
    }

    /// Split an image into its header and sections, checking that each
    /// section starts where the header's offset table says, that the
    /// sections fill the image, and that the CRC matches.
    fn decode_eif(eif: &[u8]) -> (EifHeader, Vec<(u16, &[u8])>) {
        let (header, _) = EifHeader::read_from_prefix(eif).unwrap();
        let mut sections = Vec::new();
        let mut offset = size_of::<EifHeader>();
        for index in 0..usize::from(header.num_sections.get()) {
            assert_eq!(header.section_offsets[index].get(), offset as u64);
            let (section, rest) = EifSectionHeader::read_from_prefix(&eif[offset..]).unwrap();
            assert_eq!(header.section_sizes[index].get(), section.size.get());
            let size = usize::try_from(section.size.get()).unwrap();
            sections.push((section.section_type.get(), &rest[..size]));
            offset += size_of::<EifSectionHeader>() + size;
        }
        assert_eq!(offset, eif.len());

        let mut hasher = Crc32Hasher::new();
        hasher.update(&eif[..EIF_CRC32_OFFSET]);
        hasher.update(&eif[EIF_CRC32_OFFSET + 4..]);
        assert_eq!(hasher.finalize(), header.eif_crc32.get());
        (header, sections)
    }

    #[test]
    fn test_eif_builder_reuses_descriptors() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        let initrd_path = dir.as_path().join("initrd");
        fs::write(&kernel_path, b"FAKE_KERNEL_DATA_1234").unwrap();
        fs::write(&initrd_path, b"FAKE_INITRD_DATA_5678").unwrap();
        let kernel_file = File::open(&kernel_path).unwrap();
        let initrd_file = File::open(&initrd_path).unwrap();

        // A failed InstanceStart is retryable, so build_eif can be called more
        // than once on the same descriptors.
        let first = build_eif(
            &kernel_file,
            Some(&initrd_file),
            "",
            256 * 1024 * 1024,
            2,
            0,
        )
        .unwrap();
        let second = build_eif(
            &kernel_file,
            Some(&initrd_file),
            "",
            256 * 1024 * 1024,
            2,
            0,
        )
        .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn test_eif_builder() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        let initrd_path = dir.as_path().join("initrd");

        fs::write(&kernel_path, b"FAKE_KERNEL_DATA_1234").unwrap();
        fs::write(&initrd_path, b"FAKE_INITRD_DATA_5678").unwrap();

        let kernel_file = File::open(&kernel_path).unwrap();
        let initrd_file = File::open(&initrd_path).unwrap();

        let mem = 256 * 1024 * 1024; // 256 MiB
        let cpus = 2;
        let pci_flags = 0;
        let eif = build_eif(
            &kernel_file,
            Some(&initrd_file),
            "console=ttyS0",
            mem,
            cpus,
            pci_flags,
        )
        .unwrap();

        let (header, sections) = decode_eif(&eif);
        assert_eq!(header.magic, EIF_MAGIC);
        assert_eq!(header.version.get(), EIF_HDR_VERSION);
        assert_eq!(header.default_mem.get(), mem);
        assert_eq!(header.default_cpus.get(), cpus);
        assert_eq!(header.reserved.get(), 0);
        // Kernel, cmdline, ramdisk, then metadata, as the NE hypervisor expects.
        let types: Vec<u16> = sections
            .iter()
            .map(|&(section_type, _)| section_type)
            .collect();
        assert_eq!(
            types,
            [
                EIF_SECTION_KERNEL,
                EIF_SECTION_CMDLINE,
                EIF_SECTION_RAMDISK,
                EIF_SECTION_METADATA
            ]
        );
        assert_eq!(sections[0].1, b"FAKE_KERNEL_DATA_1234");
        assert_eq!(sections[1].1, b"console=ttyS0");
        assert_eq!(sections[2].1, b"FAKE_INITRD_DATA_5678");
    }

    #[test]
    fn test_is_eif() {
        let dir = TempDir::new().unwrap();

        // A file starting with EIF magic should be detected
        let eif_path = dir.as_path().join("test.eif");
        let mut data = EIF_MAGIC.to_vec();
        data.extend_from_slice(&[0u8; 100]);
        fs::write(&eif_path, &data).unwrap();
        assert!(is_eif(&File::open(&eif_path).unwrap()));

        // A raw kernel (not EIF) should not be detected
        let kernel_path = dir.as_path().join("vmlinux");
        fs::write(&kernel_path, b"\x7fELF_fake_kernel").unwrap();
        assert!(!is_eif(&File::open(&kernel_path).unwrap()));

        // Empty file should return false
        let empty_path = dir.as_path().join("empty");
        fs::write(&empty_path, b"").unwrap();
        assert!(!is_eif(&File::open(&empty_path).unwrap()));
    }

    #[test]
    fn test_eif_empty_kernel_error() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        let initrd_path = dir.as_path().join("initrd");

        fs::write(&kernel_path, b"").unwrap();
        fs::write(&initrd_path, b"initrd").unwrap();

        let kernel_file = File::open(&kernel_path).unwrap();
        let initrd_file = File::open(&initrd_path).unwrap();

        let result = build_eif(
            &kernel_file,
            Some(&initrd_file),
            "",
            256 * 1024 * 1024,
            2,
            0,
        );
        assert!(matches!(result, Err(EifError::EmptyKernel)));
    }

    #[test]
    fn test_eif_no_initrd() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        fs::write(&kernel_path, b"FAKE_KERNEL").unwrap();
        let kernel_file = File::open(&kernel_path).unwrap();

        let eif = build_eif(&kernel_file, None, "console=ttyS0", 256 * 1024 * 1024, 2, 0).unwrap();
        assert_eq!(&eif[0..4], &EIF_MAGIC);
        // Without initrd: kernel + cmdline + metadata = 3 sections.
        assert_eq!(u16::from_be_bytes([eif[26], eif[27]]), 3);
    }

    #[test]
    fn test_eif_empty_initrd() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        let initrd_path = dir.as_path().join("initrd");
        fs::write(&kernel_path, b"FAKE_KERNEL").unwrap();
        fs::write(&initrd_path, b"").unwrap();
        let kernel_file = File::open(&kernel_path).unwrap();
        let initrd_file = File::open(&initrd_path).unwrap();

        let eif = build_eif(
            &kernel_file,
            Some(&initrd_file),
            "",
            256 * 1024 * 1024,
            2,
            0,
        )
        .unwrap();
        // A present but empty initrd keeps its ramdisk section.
        let (_, sections) = decode_eif(&eif);
        assert_eq!(sections.len(), 4);
        assert_eq!(sections[2], (EIF_SECTION_RAMDISK, &b""[..]));
    }

    #[test]
    fn test_eif_pcie_flags() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        fs::write(&kernel_path, b"FAKE_KERNEL").unwrap();
        let kernel_file = File::open(&kernel_path).unwrap();

        let pcie_flags = EIF_HDR_FLAG_PCIE | EIF_HDR_FLAG_PCIE_VIRTIO;
        let eif = build_eif(&kernel_file, None, "", 256 * 1024 * 1024, 2, pcie_flags).unwrap();

        // Flags field is at offset 6..8 (big-endian u16, after magic(4) + version(2)).
        let header_flags = u16::from_be_bytes([eif[6], eif[7]]);
        assert_eq!(header_flags & EIF_HDR_FLAG_PCIE, EIF_HDR_FLAG_PCIE);
        assert_eq!(
            header_flags & EIF_HDR_FLAG_PCIE_VIRTIO,
            EIF_HDR_FLAG_PCIE_VIRTIO
        );
        assert_eq!(header_flags & EIF_HDR_FLAG_PCIE_HOTPLUG, 0);
        // Arch bits should still be present.
        assert_eq!(header_flags & EIF_ARCH_FLAG, EIF_ARCH_FLAG);
    }

    #[test]
    fn test_eif_write_stays_within_destination() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        let kernel = [0xa5u8; 8193];
        fs::write(&kernel_path, kernel).unwrap();
        let kernel_file = File::open(&kernel_path).unwrap();
        let image = EifImage::new(
            &kernel_file,
            kernel_path.to_str().unwrap(),
            None,
            String::new(),
            256 * 1024 * 1024,
            2,
            0,
        )
        .unwrap();

        // Guard bytes on both sides of the destination must survive the write.
        let mut bytes = vec![0x5a; image.size() + 64];
        image.write(&mut bytes[32..]).unwrap();

        let (before, rest) = bytes.split_at(32);
        let (eif, after) = rest.split_at(image.size());
        assert_eq!(before, [0x5a; 32]);
        assert_eq!(after, [0x5a; 32]);
        let (_, sections) = decode_eif(eif);
        assert!(sections[0] == (EIF_SECTION_KERNEL, &kernel[..]));
    }

    #[test]
    fn test_eif_kernel_truncated_after_sizing() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        fs::write(&kernel_path, b"kernel").unwrap();
        let kernel_file = File::open(&kernel_path).unwrap();
        let image = EifImage::new(
            &kernel_file,
            kernel_path.to_str().unwrap(),
            None,
            String::new(),
            256 * 1024 * 1024,
            2,
            0,
        )
        .unwrap();

        // The image was sized for six kernel bytes; the file now holds one.
        fs::write(&kernel_path, b"k").unwrap();

        let err = write_image(&image).unwrap_err();
        assert!(
            matches!(&err, EifError::Read { op: "read", kind: FileKind::Kernel, path, source }
                if path == kernel_path.to_str().unwrap() && source.kind() == ErrorKind::UnexpectedEof),
            "{err}"
        );
    }

    #[test]
    fn test_eif_grown_kernel_keeps_sized_length() {
        let dir = TempDir::new().unwrap();
        let kernel_path = dir.as_path().join("kernel");
        fs::write(&kernel_path, b"kernel").unwrap();
        let kernel_file = File::open(&kernel_path).unwrap();
        let image = EifImage::new(
            &kernel_file,
            kernel_path.to_str().unwrap(),
            None,
            String::new(),
            256 * 1024 * 1024,
            2,
            0,
        )
        .unwrap();

        // Bytes appended after sizing are not part of the image.
        fs::OpenOptions::new()
            .append(true)
            .open(&kernel_path)
            .unwrap()
            .write_all(b" and more")
            .unwrap();

        let eif = write_image(&image).unwrap();
        let (_, sections) = decode_eif(&eif);
        assert_eq!(sections[0], (EIF_SECTION_KERNEL, &b"kernel"[..]));
    }

    #[test]
    fn test_prebuilt_eif_copies_from_open_descriptor() {
        let dir = TempDir::new().unwrap();
        let eif_path = dir.as_path().join("image.eif");
        let bytes = b".eif\0prebuilt payload\xff";
        fs::write(&eif_path, bytes).unwrap();
        let mut eif_file = File::open(&eif_path).unwrap();

        // The copy comes from the descriptor is_eif inspected, not from the
        // path, and does not depend on where that descriptor was left.
        eif_file.seek(SeekFrom::Start(5)).unwrap();
        let image = EifImage::prebuilt(&eif_file, eif_path.to_str().unwrap()).unwrap();
        fs::remove_file(&eif_path).unwrap();
        fs::write(&eif_path, b"replacement file").unwrap();

        // A retried InstanceStart copies again, this time from EOF.
        for _ in 0..2 {
            assert_eq!(write_image(&image).unwrap(), bytes);
        }
    }

    #[test]
    fn test_prebuilt_eif_truncated_after_sizing() {
        let dir = TempDir::new().unwrap();
        let eif_path = dir.as_path().join("image.eif");
        fs::write(&eif_path, b".eif payload").unwrap();
        let eif_file = File::open(&eif_path).unwrap();
        let name = eif_path.to_str().unwrap();
        let image = EifImage::prebuilt(&eif_file, name).unwrap();

        fs::write(&eif_path, b".eif").unwrap();

        let err = write_image(&image).unwrap_err();
        assert!(
            matches!(&err, EifError::Read { op: "read", kind: FileKind::Eif, path, source }
                if path == name && source.kind() == ErrorKind::UnexpectedEof),
            "{err}"
        );
    }

    #[test]
    fn test_eif_layout_overflow() {
        // Two sparse payloads of about 2^63 bytes each would wrap a u64 layout.
        let half = u64::MAX / 2;
        assert!(matches!(
            EifHeader::new(half, Some(half), 0, 0, 0, 0),
            Err(EifError::SizeOverflow)
        ));
        assert!(matches!(
            EifHeader::new(u64::MAX, None, 0, 0, 0, 0),
            Err(EifError::SizeOverflow)
        ));
    }
}
