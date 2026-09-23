// Copyright 2026 Superserve AI. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-process userfaultfd handler for snapshot restore.
//!
//! A handler thread, spawned by [`setup`] and joined when the returned [`Handler`] is
//! dropped, serves guest page faults via `UFFDIO_COPY` from a memory-mapped snapshot
//! file. The snapshot is mapped `MAP_PRIVATE` without `MAP_POPULATE` so pages stay
//! demand-paged from disk.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;

use userfaultfd::{Error as UffdCrateError, Event, FeatureFlags, Uffd, UffdBuilder};

use crate::persist::GuestRegionUffdMapping;
use crate::seccomp::{BpfProgram, apply_filter};
use crate::vmm_config::machine_config::HugePageConfig;
use crate::vstate::memory::{self, GuestMemoryState, GuestRegionMmap, MemoryError};

/// Poll timeout between shutdown-channel checks. Bounds how long a handler thread takes
/// to notice that the VM is going away.
const POLL_TIMEOUT_MS: i32 = 100;

/// Atomic counters maintained by the handler thread. Read via [`Handler::stats`] for
/// observability; not used for synchronization, hence `Ordering::Relaxed` throughout.
#[derive(Default, Debug)]
struct Stats {
    faults_served: AtomicU64,
    faults_deferred: AtomicU64,
    faults_failed_transient: AtomicU64,
    prefetch_served: AtomicU64,
    prefetch_eexist: AtomicU64,
    prefetch_eagain: AtomicU64,
    prefetch_failed: AtomicU64,
    recorded_offsets: AtomicU64,
}

/// Snapshot of [`Stats`] returned to external callers. Each field is a monotonic counter
/// of events since the handler started, except `recorded_offsets`, which is the count of
/// unique offsets currently held by the in-memory recorder (template-build mode only).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Count of guest page faults the handler resolved by copying a page from the
    /// snapshot into guest memory.
    pub faults_served: u64,
    /// Count of EAGAIN-deferred page-fault attempts. A single faulting address can
    /// contribute multiple increments if its `UFFDIO_COPY` is deferred more than once.
    pub faults_deferred: u64,
    /// Count of page-fault servicing attempts that hit an unexpected ioctl error and
    /// could not be completed. Each increment is paired with an `error!` log entry.
    pub faults_failed_transient: u64,
    /// Count of prefetcher `UFFDIO_COPY` calls that completed successfully.
    pub prefetch_served: u64,
    /// Count of prefetcher copies skipped because the page had already been faulted in
    /// by an on-demand handler call (an expected race; benign).
    pub prefetch_eexist: u64,
    /// Count of prefetcher copies that returned EAGAIN because a REMOVE event was
    /// queued ahead of them.
    pub prefetch_eagain: u64,
    /// Count of prefetcher copies that hit an unexpected error; each increment is paired
    /// with a `warn!` log entry.
    pub prefetch_failed: u64,
    /// Number of unique page offsets the in-memory recorder is currently holding
    /// (template-build mode only; zero otherwise).
    pub recorded_offsets: u64,
}

impl Stats {
    fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            faults_served: self.faults_served.load(Ordering::Relaxed),
            faults_deferred: self.faults_deferred.load(Ordering::Relaxed),
            faults_failed_transient: self.faults_failed_transient.load(Ordering::Relaxed),
            prefetch_served: self.prefetch_served.load(Ordering::Relaxed),
            prefetch_eexist: self.prefetch_eexist.load(Ordering::Relaxed),
            prefetch_eagain: self.prefetch_eagain.load(Ordering::Relaxed),
            prefetch_failed: self.prefetch_failed.load(Ordering::Relaxed),
            recorded_offsets: self.recorded_offsets.load(Ordering::Relaxed),
        }
    }
}

/// Configuration for an internal-UFFD-backed restore.
#[derive(Clone, Debug)]
pub struct Config {
    /// Snapshot memory file backing guest RAM. In layered mode this is the overlay
    /// (diff) file; pages absent from it are served from `base_path`.
    pub snapshot_path: PathBuf,
    /// Base (template) memory file. When set, the restore is layered: a page is
    /// served from `snapshot_path` if present there, else from this base.
    pub base_path: Option<PathBuf>,
    /// Recorded page-access trace replayed as prefetch when present.
    pub access_log_path: Option<PathBuf>,
    /// When set, the handler records each served page offset and suppresses prefetch.
    pub record_to: Option<PathBuf>,
    /// When true, an unexpected handler exit (error or panic, not a clean shutdown)
    /// aborts the Firecracker process instead of leaving the guest to hang on its next
    /// page fault — so a supervisor sees a dead VM rather than a frozen one.
    pub abort_on_handler_death: bool,
}

/// Owning handle for a handler thread. Drop signals shutdown and joins the thread.
pub struct Handler {
    shutdown_tx: mpsc::Sender<()>,
    drain_tx: mpsc::SyncSender<mpsc::SyncSender<()>>,
    stats: Arc<Stats>,
    thread: Option<thread::JoinHandle<()>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler")
            .field("running", &self.thread.is_some())
            .finish()
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Handler {
    /// Block until the handler thread has drained every UFFD event currently queued by the
    /// kernel. Callers must hold the VM paused so no new faults can arrive between drain
    /// and the operation that requires a stable memory view (e.g. snapshot dump).
    pub fn drain_pending(&self) -> Result<(), DrainError> {
        let (ack_tx, ack_rx) = mpsc::sync_channel::<()>(0);
        self.drain_tx
            .send(ack_tx)
            .map_err(|_| DrainError::HandlerExited)?;
        ack_rx.recv().map_err(|_| DrainError::NoAck)
    }

    /// Snapshot of the handler's counters at the time of the call.
    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }
}

/// Failure modes for [`Handler::drain_pending`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DrainError {
    /// Handler thread has exited; the drain request was not delivered.
    HandlerExited,
    /// Drain request was delivered but the handler did not acknowledge completion (thread likely died mid-drain).
    NoAck,
}

/// Errors returned during setup of the in-process handler.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum InternalUffdError {
    /// Failed to allocate guest memory: {0}
    Memory(#[from] MemoryError),
    /// Failed to create userfaultfd: {0}
    Create(UffdCrateError),
    /// Failed to register memory region with userfaultfd: {0}
    Register(UffdCrateError),
    /// Failed to open or mmap snapshot file: {0}
    OpenSnapshot(std::io::Error),
    /// Failed to open access-log output file: {0}
    OpenRecorder(std::io::Error),
    /// Failed to duplicate userfaultfd descriptor: {0}
    DupFd(std::io::Error),
    /// Failed to spawn handler thread: {0}
    SpawnThread(std::io::Error),
    /// Invalid layered restore: {0}
    LayeredInvalid(String),
    /// Failed to inspect filesystem for layered restore: {0}
    LayeredSetup(std::io::Error),
}

/// Allocate anonymous guest memory, create + register a userfaultfd, and start a handler
/// thread that serves page faults from `cfg.snapshot_path`.
///
/// All file I/O (opening + mmap of the snapshot) happens on the calling thread before the
/// handler is spawned, so the runtime filesystem syscalls do not need to be present in the
/// VMM seccomp allowlist that gates the handler thread.
pub fn setup(
    cfg: Config,
    mem_state: &GuestMemoryState,
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
    vmm_filter: Arc<BpfProgram>,
) -> Result<(Vec<GuestRegionMmap>, Uffd, Handler), InternalUffdError> {
    let guest_memory = memory::anonymous(mem_state.regions(), track_dirty_pages, huge_pages)?;
    let page_size = huge_pages.page_size();
    let abort_on_handler_death = cfg.abort_on_handler_death;

    let mut builder = UffdBuilder::new();
    builder.require_features(FeatureFlags::EVENT_REMOVE);
    let uffd = builder
        .close_on_exec(true)
        .non_blocking(true)
        .user_mode_only(false)
        .create()
        .map_err(InternalUffdError::Create)?;

    let mut mappings = Vec::with_capacity(guest_memory.len());
    let mut offset = 0u64;
    for region in guest_memory.iter() {
        uffd.register(region.as_ptr().cast(), region.size())
            .map_err(InternalUffdError::Register)?;
        #[allow(deprecated)]
        mappings.push(GuestRegionUffdMapping {
            base_host_virt_addr: region.as_ptr() as u64,
            size: region.size(),
            offset,
            page_size,
            page_size_kib: page_size,
        });
        offset += region.size() as u64;
    }

    let total_mem = offset; // sum of region sizes = total guest RAM
    let overlay = mmap_snapshot(&cfg.snapshot_path).map_err(InternalUffdError::OpenSnapshot)?;
    // Layered restore: mmap the base (template) and resolve which pages the overlay
    // provides, so a page absent from the overlay falls through to the base. Validate
    // sizes up front so a malformed/short file fails the restore loudly instead of
    // risking an out-of-bounds page source (or a handler-thread panic) at fault time.
    let (base, present) = match cfg.base_path.as_deref() {
        Some(base_path) => {
            let base = mmap_snapshot(base_path).map_err(InternalUffdError::OpenSnapshot)?;
            // Presence comes from the side-car when one was saved with the overlay;
            // extent scanning is the fallback for overlays that predate it. The
            // filesystem-granularity precondition only guards the scan — a side-car
            // carries presence explicitly and is valid on any filesystem. Gate on
            // existence and validate before parsing, so geometry violations surface
            // as validate_layered's precise errors (short overlay, huge pages), not
            // as side-car mismatches.
            let has_sidecar = presence_sidecar_path(&cfg.snapshot_path).exists();
            let scan_blksize = if has_sidecar {
                None
            } else {
                Some(
                    std::fs::metadata(&cfg.snapshot_path)
                        .map_err(InternalUffdError::LayeredSetup)?
                        .blksize(),
                )
            };
            validate_layered(
                overlay.size,
                base.size,
                total_mem,
                page_size,
                crate::arch::host_page_size(),
                scan_blksize,
            )?;
            let present = match read_presence_sidecar(
                &cfg.snapshot_path,
                page_size,
                overlay.size.div_ceil(page_size),
            )? {
                Some(pm) => pm,
                // The side-car existed when the granularity gate ran but is gone at
                // parse time; refuse rather than scan extents that skipped the gate.
                None if has_sidecar => {
                    return Err(InternalUffdError::LayeredInvalid(format!(
                        "presence side-car for {:?} disappeared during restore setup",
                        cfg.snapshot_path
                    )));
                }
                None => {
                    log::warn!(
                        "uffd-internal: no presence side-car next to {:?}; falling back \
                         to extent scanning, which is only sound if the overlay was \
                         never copied by a tool that rewrites sparse extents",
                        cfg.snapshot_path
                    );
                    scan_present_pages(&cfg.snapshot_path, page_size)
                        .map_err(InternalUffdError::LayeredSetup)?
                }
            };
            (Some(base), Some(present))
        }
        None => (None, None),
    };
    let backing = Backing {
        overlay,
        base,
        present,
        page_size,
    };

    // Recording disables prefetch so the captured trace reflects guest-driven access
    // order instead of pages pulled in by the prefetcher.
    let prefetch_offsets = if cfg.record_to.is_some() {
        Vec::new()
    } else {
        cfg.access_log_path
            .as_deref()
            .map(|p| load_prefetch_offsets(p, page_size))
            .unwrap_or_default()
    };
    let recorder = match cfg.record_to.as_deref() {
        Some(path) => Some(Recorder::create(path).map_err(InternalUffdError::OpenRecorder)?),
        None => None,
    };

    // Duplicate the fd so the handler thread holds an independent owner. The kernel
    // UFFD registration stays alive until every refcount on the fd is closed.
    // SAFETY: `uffd` is alive for the duration of this call and exposes a valid open fd.
    let dup_fd = unsafe { libc::dup(uffd.as_raw_fd()) };
    if dup_fd < 0 {
        return Err(InternalUffdError::DupFd(std::io::Error::last_os_error()));
    }
    // SAFETY: `dup_fd` was just returned by `dup()` and is owned exclusively by the new
    // `Uffd` from this point on. No other code retains the raw value.
    let handler_uffd = unsafe { Uffd::from_raw_fd(dup_fd) };

    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let (drain_tx, drain_rx) = mpsc::sync_channel::<mpsc::SyncSender<()>>(0);
    let stats = Arc::new(Stats::default());
    let stats_for_thread = Arc::clone(&stats);
    let thread = thread::Builder::new()
        .name("uffd-internal".into())
        .spawn(move || {
            // catch_unwind so a handler panic also counts as an unexpected exit.
            // AssertUnwindSafe is sound: the captured state is never reused after this.
            let clean = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run(
                    handler_uffd,
                    mappings,
                    page_size,
                    backing,
                    prefetch_offsets,
                    recorder,
                    vmm_filter,
                    stats_for_thread,
                    shutdown_rx,
                    drain_rx,
                )
            }))
            .unwrap_or_else(|_| {
                log::error!("uffd-internal: handler thread panicked");
                HandlerExit::Unexpected
            });
            if clean == HandlerExit::Unexpected {
                // Handler gone while the guest may still fault. Log always; abort only
                // when gated on, so the VM dies visibly instead of hanging silently.
                log::error!("uffd-internal: handler exited unexpectedly");
                if abort_on_handler_death {
                    log::error!(
                        "uffd-internal: aborting Firecracker so the dead VM is surfaced, not frozen"
                    );
                    std::process::exit(UFFD_HANDLER_DEATH_EXIT_CODE);
                }
            }
        })
        .map_err(InternalUffdError::SpawnThread)?;

    Ok((
        guest_memory,
        uffd,
        Handler {
            shutdown_tx,
            drain_tx,
            stats,
            thread: Some(thread),
        },
    ))
}

struct SnapshotMmap {
    addr: *const u8,
    size: usize,
}

// SAFETY: the mapping is read-only and owned exclusively by the handler thread; no
// concurrent mutation is possible across threads.
unsafe impl Send for SnapshotMmap {}

impl Drop for SnapshotMmap {
    fn drop(&mut self) {
        if !self.addr.is_null() && self.size > 0 {
            // SAFETY: `addr` and `size` are the exact arguments returned by `mmap()` in
            // `mmap_snapshot`, this is the only owner of the mapping, and no live pointer
            // into it survives past this `drop`.
            unsafe {
                libc::munmap(self.addr as *mut _, self.size);
            }
        }
    }
}

fn mmap_snapshot(path: &Path) -> std::io::Result<SnapshotMmap> {
    let file = std::fs::File::open(path)?;
    let size = file.metadata()?.len() as usize;
    // MAP_POPULATE intentionally omitted so pages stay demand-paged from the file.
    // SAFETY: `file` is open and its fd is valid for the duration of the mmap call;
    // `size` is the file size in bytes; PROT_READ requires no special alignment of the
    // returned address.
    let addr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            size,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    Ok(SnapshotMmap {
        addr: addr.cast(),
        size,
    })
}

/// One bit per guest page: set ⇒ the page is present in the overlay (diff) file,
/// clear ⇒ it must be served from the base. Built once at setup from the overlay's
/// allocated extents (see `scan_present_pages`).
#[derive(Debug)]
pub(crate) struct PresenceBitmap {
    pub(crate) bits: Vec<u64>,
}

impl PresenceBitmap {
    fn with_pages(n: usize) -> Self {
        Self {
            bits: vec![0u64; n.div_ceil(64)],
        }
    }
    fn set(&mut self, i: usize) {
        self.bits[i >> 6] |= 1u64 << (i & 63);
    }
    fn is_set(&self, i: usize) -> bool {
        // Out-of-range ⇒ not present (fall through to base). `setup` already
        // guarantees the overlay covers all guest pages, so this is defense in
        // depth against a panic on the handler thread (which would hang the VM).
        let word = i >> 6;
        word < self.bits.len() && self.bits[word] & (1u64 << (i & 63)) != 0
    }
}

/// Validates the size and filesystem-granularity preconditions for a layered restore.
/// Both layers must cover all guest RAM; the page size must not exceed the host page
/// size (the overlay is dumped at host-page granularity); and, when presence will be
/// inferred by scanning extents (`scan_blksize` is `Some`), the filesystem's
/// allocation unit must be <= the page size so hole/data extents are page-granular.
/// A side-car-backed restore passes `None`: its presence bitmap is explicit and does
/// not depend on the extent map. Each violation would otherwise silently serve wrong
/// or zero pages, so it's a hard error. Pure (takes sizes, not files) so the reject
/// paths are unit-testable.
fn validate_layered(
    overlay_size: usize,
    base_size: usize,
    total_mem: u64,
    page_size: usize,
    host_page_size: usize,
    scan_blksize: Option<u64>,
) -> Result<(), InternalUffdError> {
    if (overlay_size as u64) < total_mem {
        return Err(InternalUffdError::LayeredInvalid(format!(
            "overlay is {overlay_size} bytes, smaller than guest RAM {total_mem}"
        )));
    }
    if (base_size as u64) < total_mem {
        return Err(InternalUffdError::LayeredInvalid(format!(
            "base is {base_size} bytes, smaller than guest RAM {total_mem}"
        )));
    }
    // dump_dirty writes dirtied pages at the host page size and the save stamps the
    // side-car with it, so layered restore requires exactly host-page granularity:
    // a huge-page guest (page_size > host) would leave a partially-dirty huge page
    // as host-page data+hole extents while presence marks the whole huge page, and
    // a sub-host page size (e.g. the default 4096 on a 16K/64K-page host) would
    // misindex the bitmap and misalign every UFFDIO_COPY.
    if page_size != host_page_size {
        return Err(InternalUffdError::LayeredInvalid(format!(
            "layered restore requires the host page size ({host_page_size}), but the \
             restore page size is {page_size}; huge-page overlays are unsupported"
        )));
    }
    // Scanned presence is page-granular only when the filesystem's allocation unit is
    // <= the page size (true on ext4 with 4K blocks). On a larger-granularity FS (e.g.
    // ZFS recordsize), SEEK_DATA over-reports clean pages as present and serves zeros.
    if let Some(blksize) = scan_blksize {
        if blksize > page_size as u64 {
            return Err(InternalUffdError::LayeredInvalid(format!(
                "overlay filesystem block size {blksize} > page size {page_size}; \
                 layered restore without a presence side-car needs page-granular holes"
            )));
        }
    }
    Ok(())
}

/// Scan `path`'s allocated extents via `SEEK_DATA`/`SEEK_HOLE` and mark every page
/// that overlaps real data. `dump_dirty` writes dirtied pages as real extents and
/// leaves clean pages as holes (no zero-skip), so a present extent == an overlay
/// page and a hole == "fall through to base".
pub(crate) fn scan_present_pages(path: &Path, page_size: usize) -> std::io::Result<PresenceBitmap> {
    let file = std::fs::File::open(path)?;
    let size = file.metadata()?.len();
    let npages = (size as usize).div_ceil(page_size);
    let mut pm = PresenceBitmap::with_pages(npages);
    crate::utils::sparse::for_each_data_extent(&file, size, |start, end| {
        let start_pg = start as usize / page_size;
        let end_pg = (end as usize).div_ceil(page_size).min(npages);
        for p in start_pg..end_pg {
            pm.set(p);
        }
    })?;
    Ok(pm)
}

/// Magic + format version prefix of the presence side-car. Bump the trailing
/// digit on any layout change; readers reject unknown prefixes outright.
///
/// The layout is deliberately a fixed hand-rolled format rather than the bitcode
/// encoding the vmstate side-car uses: this file is a cross-host durability
/// artifact that out-of-band tooling must be able to parse and regenerate, and
/// its encoding must not shift under a serialization-dependency upgrade.
const PRESENCE_MAGIC: [u8; 8] = *b"FCPRSNC1";
/// Side-car header: magic, page_size (u64 LE), npages (u64 LE). The bitmap words
/// follow, then a trailing CRC64 (LE) over everything before it.
const PRESENCE_HEADER_LEN: usize = 24;
/// Single-byte side-car content marking a memory file whose save could not
/// derive a presence bitmap (a diff merged into a pre-side-car overlay whose
/// extent scan can't be trusted). Distinct from the 0-byte torn-save sentinel so
/// a layered restore can name each cause precisely.
pub(crate) const PRESENCE_UNDERIVABLE: u8 = 0x55;

/// Path of the page-presence side-car for a given memory file path.
pub fn presence_sidecar_path(mem_path: &Path) -> PathBuf {
    let mut p = mem_path.as_os_str().to_owned();
    p.push(".presence");
    p.into()
}

/// Write `bytes` to `path` (create/truncate in place — `rename`/`unlink` are not
/// in the seccomp allowlist), fsync the file, then fsync the parent directory so
/// the dirent itself is durable. Without the directory fsync a crash can keep
/// the data but lose a newly created file's directory entry — for a presence
/// side-car that reads back as "no side-car" and silently re-enables extent
/// scanning of a torn merge.
pub(crate) fn write_file_durable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

impl PresenceBitmap {
    /// Serialize as a presence side-car: magic, page size, page count, bitmap
    /// words, trailing CRC64. Kept as a pair with [`PresenceBitmap::decode`] so
    /// any layout change is a single-impl edit.
    fn encode(bits: &[u64], page_size: usize, npages: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PRESENCE_HEADER_LEN + bits.len() * 8 + 8);
        bytes.extend_from_slice(&PRESENCE_MAGIC);
        bytes.extend_from_slice(&(page_size as u64).to_le_bytes());
        bytes.extend_from_slice(&(npages as u64).to_le_bytes());
        for w in bits {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let crc = crc64::crc64(0, &bytes);
        bytes.extend_from_slice(&crc.to_le_bytes());
        bytes
    }

    /// Parse and validate a presence side-car produced by [`PresenceBitmap::encode`].
    /// Rejects wrong magic, page-size/page-count mismatches against the overlay,
    /// wrong total length, and CRC failures — a flipped word would otherwise
    /// silently mis-layer 64 pages.
    fn decode(
        bytes: &[u8],
        path: &Path,
        page_size: usize,
        expected_npages: usize,
    ) -> Result<PresenceBitmap, InternalUffdError> {
        let invalid = |msg: String| InternalUffdError::LayeredInvalid(msg);
        let words = expected_npages.div_ceil(64);
        let expected_len = PRESENCE_HEADER_LEN + words * 8 + 8;
        if bytes.len() < PRESENCE_HEADER_LEN + 8 || bytes[..8] != PRESENCE_MAGIC {
            return Err(invalid(format!(
                "presence side-car at {path:?} has an unrecognized header"
            )));
        }
        if bytes.len() != expected_len {
            return Err(invalid(format!(
                "presence side-car at {path:?} is {} bytes, expected {expected_len}",
                bytes.len()
            )));
        }
        let (payload, crc_bytes) = bytes.split_at(bytes.len() - 8);
        let stored_crc = u64::from_le_bytes(crc_bytes.try_into().unwrap());
        let computed_crc = crc64::crc64(0, payload);
        if stored_crc != computed_crc {
            return Err(invalid(format!(
                "presence side-car at {path:?} fails its checksum \
                 (stored {stored_crc:#x}, computed {computed_crc:#x})"
            )));
        }
        let u64_at = |off: usize| u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        let (sc_page_size, sc_npages) = (u64_at(8), u64_at(16));
        if sc_page_size != page_size as u64 || sc_npages != expected_npages as u64 {
            return Err(invalid(format!(
                "presence side-car at {path:?} describes page size {sc_page_size} / \
                 {sc_npages} pages, but the overlay has page size {page_size} / \
                 {expected_npages} pages"
            )));
        }
        let mut pm = PresenceBitmap::with_pages(expected_npages);
        for (i, chunk) in payload[PRESENCE_HEADER_LEN..].chunks_exact(8).enumerate() {
            pm.bits[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        Ok(pm)
    }
}

/// Write `<mem_path>.presence`: an explicit page-presence bitmap for the memory
/// file. One set bit per file page whose content the memory file provides.
///
/// Persisting presence explicitly is the point of the side-car: a sparse diff's
/// extent map also encodes presence (written extent = dirty, hole = clean), but
/// file transfers don't reliably preserve extents — a copy that materializes
/// holes flips clean pages into "present, all zeros", and one that punches holes
/// through written zero pages flips dirtied-to-zero pages into "absent, read the
/// base". The bitmap survives any byte-preserving transfer.
pub(crate) fn write_presence_bitmap(
    mem_path: &Path,
    page_size: usize,
    npages: usize,
    bits: &[u64],
) -> std::io::Result<()> {
    if bits.len() != npages.div_ceil(64) {
        return Err(std::io::Error::other(format!(
            "presence bitmap has {} words, expected {} for {npages} pages",
            bits.len(),
            npages.div_ceil(64)
        )));
    }
    write_file_durable(
        &presence_sidecar_path(mem_path),
        &PresenceBitmap::encode(bits, page_size, npages),
    )
}

/// Load `<overlay>.presence` if it exists. `Ok(None)` ⇒ no side-car (a pre-side-car
/// snapshot) and the caller falls back to scanning extents. A side-car that exists
/// but doesn't describe this overlay is a hard error, never a fallback: an empty
/// file is the sentinel for an interrupted save or a memory file with no derivable
/// presence (full snapshot, or a diff merged on a coarse-allocation filesystem),
/// and a page-size or page-count mismatch means the bitmap belongs to a different
/// memory file. Scanning extents in those cases would silently reintroduce
/// extent-inferred presence — the exact failure the side-car exists to prevent.
///
/// Known limit: validation is geometric only. A side-car from a *different
/// generation* of a same-sized overlay (e.g. a transfer replaced the overlay but
/// died before replacing the side-car) passes every check here and silently
/// resolves pages against the wrong bitmap. Nothing in the pair binds them
/// together, so the transfer layer must move the two files atomically
/// (temp names + rename) — a mismatched pair is undetectable at restore.
pub(crate) fn read_presence_sidecar(
    overlay_path: &Path,
    page_size: usize,
    expected_npages: usize,
) -> Result<Option<PresenceBitmap>, InternalUffdError> {
    let path = presence_sidecar_path(overlay_path);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(InternalUffdError::LayeredSetup(e)),
    };
    // "(torn snapshot save)" is a load-bearing marker: orchestrators match this
    // exact substring (shared with the vmstate side-car's torn error) to classify
    // the failure as data loss and re-snapshot, rather than as a permanent
    // precondition failure. Keep the wording in sync with persist.rs.
    if bytes.is_empty() {
        return Err(InternalUffdError::LayeredInvalid(format!(
            "presence side-car at {path:?} is empty (torn snapshot save)"
        )));
    }
    if bytes == [PRESENCE_UNDERIVABLE] {
        return Err(InternalUffdError::LayeredInvalid(format!(
            "presence side-car at {path:?} marks the memory file as un-layerable: its \
             save merged a diff without a prior side-car on a filesystem whose extent \
             scan cannot be trusted (see save-time warnings)"
        )));
    }
    PresenceBitmap::decode(&bytes, &path, page_size, expected_npages).map(Some)
}

/// The memory backing a layered (or single-file) restore. `overlay` is the file
/// named by `Config::snapshot_path`; in layered mode `base` + `present` resolve
/// pages absent from the overlay to the template.
struct Backing {
    overlay: SnapshotMmap,
    base: Option<SnapshotMmap>,
    present: Option<PresenceBitmap>,
    // Page size is fixed for the restore's lifetime; held here so src_ptr needn't be
    // passed it on every fault.
    page_size: usize,
}

impl Backing {
    /// Source pointer for the page at `file_offset`: the overlay if the page is
    /// present there (or there is no base), else the base. The two layers are the
    /// same logical size, so `file_offset` is in bounds for whichever is chosen.
    fn src_ptr(&self, file_offset: u64) -> *const u8 {
        // setup() validates both mmaps cover all guest RAM and callers pass an in-region
        // offset; assert it so any future misuse outside setup is caught in debug builds.
        debug_assert!(
            (file_offset as usize) < self.overlay.size,
            "overlay offset out of bounds"
        );
        if let (Some(base), Some(present)) = (&self.base, &self.present) {
            debug_assert!((file_offset as usize) < base.size, "base offset out of bounds");
            let page_idx = (file_offset / self.page_size as u64) as usize;
            if !present.is_set(page_idx) {
                // SAFETY: file_offset < total guest mem size <= base mmap size.
                return unsafe { base.addr.add(file_offset as usize) };
            }
        }
        // SAFETY: file_offset < total guest mem size <= overlay mmap size.
        unsafe { self.overlay.addr.add(file_offset as usize) }
    }
}

/// Exit code used when an unexpected handler death aborts Firecracker (gated by
/// `Config::abort_on_handler_death`). 70 = EX_SOFTWARE (sysexits.h, "internal software
/// error") — chosen so the cause is recognizable in logs/process monitoring.
const UFFD_HANDLER_DEATH_EXIT_CODE: i32 = 70;

/// How the handler loop ended. `Clean` is an intentional teardown (the orchestrator
/// signalled shutdown, or Firecracker unmapped the regions as the VM goes away).
/// `Unexpected` is any error path — the handler can no longer serve faults while the
/// guest may still need them.
#[derive(Debug, PartialEq, Eq)]
enum HandlerExit {
    Clean,
    Unexpected,
}

#[allow(clippy::too_many_arguments)]
fn run(
    uffd: Uffd,
    mappings: Vec<GuestRegionUffdMapping>,
    page_size: usize,
    backing: Backing,
    prefetch_offsets: Vec<u64>,
    mut recorder: Option<Recorder>,
    vmm_filter: Arc<BpfProgram>,
    stats: Arc<Stats>,
    shutdown_rx: mpsc::Receiver<()>,
    drain_rx: mpsc::Receiver<mpsc::SyncSender<()>>,
) -> HandlerExit {
    // Apply the same seccomp filter as the VMM thread before serving any events.
    if let Err(e) = apply_filter(vmm_filter.as_slice()) {
        log::error!("uffd-internal: failed to apply seccomp filter, exiting: {e:?}");
        return HandlerExit::Unexpected;
    }

    // Pagefault addresses that returned EAGAIN because a REMOVE event was queued ahead
    // of them; retried at the top of each iteration so the REMOVE drains first.
    let mut deferred: Vec<u64> = Vec::new();
    let mut prefetch_cursor = 0usize;
    let pollfd = libc::pollfd {
        fd: uffd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };

    loop {
        if shutdown_rx.try_recv().is_ok() {
            // Drain anything the kernel has queued, then exit. The VM is paused before
            // snapshot save and before VM destroy, so no new faults arrive after this.
            // The recorder (when active) writes its trace line-by-line during record(),
            // so no shutdown-time flush is needed for it.
            drain_to_completion(
                &uffd,
                &mappings,
                &backing,
                page_size,
                &mut deferred,
                recorder.as_mut(),
                &stats,
            );
            return HandlerExit::Clean;
        }

        if let Ok(ack) = drain_rx.try_recv() {
            drain_to_completion(
                &uffd,
                &mappings,
                &backing,
                page_size,
                &mut deferred,
                recorder.as_mut(),
                &stats,
            );
            let _ = ack.send(());
        }

        // While prefetch entries remain, poll non-blocking so the loop can advance the
        // prefetcher when the kernel queue is empty. Incoming faults always preempt
        // prefetch because each iteration re-enters `poll`.
        let poll_timeout = if prefetch_cursor < prefetch_offsets.len() {
            0
        } else {
            POLL_TIMEOUT_MS
        };

        let mut pfds = [pollfd];
        // SAFETY: pfds is a single-element array on this stack frame.
        let n = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as _, poll_timeout) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            log::error!("uffd-internal: poll failed: {err}");
            return HandlerExit::Unexpected;
        }

        retry_deferred(
            &uffd,
            &mappings,
            &backing,
            page_size,
            &mut deferred,
            recorder.as_mut(),
            &stats,
        );

        if n == 0 {
            if prefetch_cursor < prefetch_offsets.len() {
                prefetch_one(
                    &uffd,
                    &mappings,
                    &backing,
                    page_size,
                    prefetch_offsets[prefetch_cursor],
                    &stats,
                );
                prefetch_cursor += 1;
            }
            continue;
        }

        loop {
            match uffd.read_event() {
                Ok(Some(ev)) => handle_event(
                    &uffd,
                    &mappings,
                    &backing,
                    page_size,
                    ev,
                    recorder.as_mut(),
                    &mut deferred,
                    &stats,
                ),
                Ok(None) => break,
                Err(UffdCrateError::SystemError(e))
                    if std::io::Error::from(e).raw_os_error() == Some(libc::EAGAIN) =>
                {
                    break;
                }
                Err(UffdCrateError::SystemError(e))
                    if std::io::Error::from(e).raw_os_error() == Some(libc::EINVAL) =>
                {
                    // EINVAL on read means firecracker has already unmapped the registered
                    // memory regions; the VM is going away. Exit cleanly.
                    return HandlerExit::Clean;
                }
                Err(e) => {
                    log::error!("uffd-internal: read_event failed: {e:?}");
                    return HandlerExit::Unexpected;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn retry_deferred(
    uffd: &Uffd,
    mappings: &[GuestRegionUffdMapping],
    backing: &Backing,
    page_size: usize,
    deferred: &mut Vec<u64>,
    mut recorder: Option<&mut Recorder>,
    stats: &Stats,
) {
    if deferred.is_empty() {
        return;
    }
    let mut still_deferred = Vec::with_capacity(deferred.len());
    for addr in deferred.drain(..) {
        match serve_pagefault(uffd, mappings, backing, page_size, addr) {
            ServeOutcome::Served => {
                stats.faults_served.fetch_add(1, Ordering::Relaxed);
                record_fault(recorder.as_deref_mut(), mappings, page_size, addr, stats);
            }
            ServeOutcome::Deferred => {
                stats.faults_deferred.fetch_add(1, Ordering::Relaxed);
                still_deferred.push(addr);
            }
            ServeOutcome::FailedTransient => {
                stats.faults_failed_transient.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    *deferred = still_deferred;
}

/// Drain every UFFD event the kernel currently has queued, retrying any deferred
/// entries until both the queue is empty and the deferred list has stopped shrinking.
///
/// **Pre-condition: the caller must pause guest vCPUs before invoking this.** Without
/// that invariant a guest that keeps page-faulting will keep `read_event` returning new
/// events and this loop will never terminate. The two existing call sites (shutdown and
/// snapshot-save drain) both pair this function with an external pause.
#[allow(clippy::too_many_arguments)]
fn drain_to_completion(
    uffd: &Uffd,
    mappings: &[GuestRegionUffdMapping],
    backing: &Backing,
    page_size: usize,
    deferred: &mut Vec<u64>,
    mut recorder: Option<&mut Recorder>,
    stats: &Stats,
) {
    loop {
        let prev_deferred = deferred.len();
        retry_deferred(
            uffd,
            mappings,
            backing,
            page_size,
            deferred,
            recorder.as_deref_mut(),
            stats,
        );

        let mut got_new = false;
        while let Ok(Some(ev)) = uffd.read_event() {
            handle_event(
                uffd,
                mappings,
                backing,
                page_size,
                ev,
                recorder.as_deref_mut(),
                deferred,
                stats,
            );
            got_new = true;
        }

        // Termination: stop only when both the kernel queue is empty (no new events)
        // and the deferred list has not shrunk (no retry progress was made). If either
        // condition fails, continue: a successful retry may have unblocked the kernel
        // queue, and a freshly-read REMOVE may have unblocked a deferred entry.
        if !got_new && deferred.len() >= prev_deferred {
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_event(
    uffd: &Uffd,
    mappings: &[GuestRegionUffdMapping],
    backing: &Backing,
    page_size: usize,
    ev: Event,
    recorder: Option<&mut Recorder>,
    deferred: &mut Vec<u64>,
    stats: &Stats,
) {
    match ev {
        Event::Pagefault { addr, .. } => {
            let addr_u64 = addr as u64;
            match serve_pagefault(uffd, mappings, backing, page_size, addr_u64) {
                ServeOutcome::Served => {
                    stats.faults_served.fetch_add(1, Ordering::Relaxed);
                    record_fault(recorder, mappings, page_size, addr_u64, stats);
                }
                ServeOutcome::Deferred => {
                    stats.faults_deferred.fetch_add(1, Ordering::Relaxed);
                    deferred.push(addr_u64);
                }
                ServeOutcome::FailedTransient => {
                    stats.faults_failed_transient.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        Event::Remove { start, end } => unregister_range(uffd, start, end, page_size),
        _ => {
            log::debug!("uffd-internal: unexpected event: {ev:?}");
        }
    }
}

/// Record the page-aligned file offset corresponding to `addr` if a recorder is active.
/// Called only after `serve_pagefault` confirms the page is resident in guest memory.
fn record_fault(
    recorder: Option<&mut Recorder>,
    mappings: &[GuestRegionUffdMapping],
    page_size: usize,
    addr: u64,
    stats: &Stats,
) {
    let Some(rec) = recorder else { return };
    let page_addr = addr & !((page_size as u64) - 1);
    if let Some(region) = mappings.iter().find(|r| {
        page_addr >= r.base_host_virt_addr && page_addr < r.base_host_virt_addr + r.size as u64
    }) {
        let offset = region.offset + (page_addr - region.base_host_virt_addr);
        if rec.record(offset) {
            stats.recorded_offsets.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Replay one entry of the recorded access trace. Outcomes are counted on `stats` so
/// EAGAIN bursts and unexpected errors are visible even though the prefetch path has no
/// caller to surface them to.
fn prefetch_one(
    uffd: &Uffd,
    mappings: &[GuestRegionUffdMapping],
    backing: &Backing,
    page_size: usize,
    offset: u64,
    stats: &Stats,
) {
    let region = match mappings
        .iter()
        .find(|r| offset >= r.offset && offset < r.offset + r.size as u64)
    {
        Some(r) => r,
        None => return,
    };
    let page_offset_in_region = (offset - region.offset) & !((page_size as u64) - 1);
    let dst = (region.base_host_virt_addr + page_offset_in_region) as *mut libc::c_void;
    // Layered: resolve the page to the overlay or base. `region.offset +
    // page_offset_in_region` is bounded by the region's file extent.
    let src = backing.src_ptr(region.offset + page_offset_in_region) as *const libc::c_void;
    // SAFETY: same constraints as in `serve_pagefault` — src within snapshot mmap, dst
    // within a region registered with this UFFD.
    let res = unsafe { uffd.copy(src, dst, page_size, true) };
    match res {
        Ok(_) => {
            stats.prefetch_served.fetch_add(1, Ordering::Relaxed);
        }
        Err(UffdCrateError::PartiallyCopied(bytes))
            if bytes == 0 || bytes == (-libc::EAGAIN) as usize =>
        {
            // REMOVE event queued ahead; on-demand fault path will retry, prefetch
            // does not attempt to recover.
            stats.prefetch_eagain.fetch_add(1, Ordering::Relaxed);
        }
        Err(UffdCrateError::CopyFailed(errno))
            if std::io::Error::from(errno).raw_os_error() == Some(libc::EEXIST) =>
        {
            // Guest already faulted this page in; expected race with on-demand path.
            stats.prefetch_eexist.fetch_add(1, Ordering::Relaxed);
        }
        Err(e) => {
            stats.prefetch_failed.fetch_add(1, Ordering::Relaxed);
            log::warn!("uffd-internal: prefetch UFFDIO_COPY failed: {e:?}");
        }
    }
}

/// Outcome of a single page-fault servicing attempt. Drives whether the caller defers,
/// records, or moves on.
#[derive(Debug, PartialEq, Eq)]
enum ServeOutcome {
    /// Page is now resident in guest memory (either freshly copied or already present).
    Served,
    /// `UFFDIO_COPY` returned EAGAIN because a REMOVE event is queued ahead; the caller
    /// should retry this address after draining subsequent events.
    Deferred,
    /// Servicing failed in an unexpected way (already logged); the page is not resident
    /// and there is no immediate path to fix it.
    FailedTransient,
}

fn serve_pagefault(
    uffd: &Uffd,
    mappings: &[GuestRegionUffdMapping],
    backing: &Backing,
    page_size: usize,
    addr: u64,
) -> ServeOutcome {
    let page_addr = addr & !((page_size as u64) - 1);
    let region = match mappings
        .iter()
        .find(|r| page_addr >= r.base_host_virt_addr && page_addr < r.base_host_virt_addr + r.size as u64)
    {
        Some(r) => r,
        None => {
            log::warn!("uffd-internal: page fault {page_addr:#x} outside known regions");
            return ServeOutcome::FailedTransient;
        }
    };
    let offset = page_addr - region.base_host_virt_addr;
    // Layered: resolve the page to the overlay or base. `region.offset + offset` is
    // bounded above by `region.size`, so it is in bounds for either mmap.
    let src = backing.src_ptr(region.offset + offset) as *const libc::c_void;
    let dst = page_addr as *mut libc::c_void;

    // SAFETY: `src` is within the snapshot mmap; `dst` is within a region registered with
    // this UFFD; both ranges are exactly `page_size` bytes long. Setting the wake bit
    // lets the faulting vCPU resume after the kernel installs the page.
    let res = unsafe { uffd.copy(src, dst, page_size, true) };
    match res {
        Ok(_) => ServeOutcome::Served,
        Err(UffdCrateError::PartiallyCopied(bytes))
            if bytes == 0 || bytes == (-libc::EAGAIN) as usize =>
        {
            ServeOutcome::Deferred
        }
        Err(UffdCrateError::CopyFailed(errno))
            if std::io::Error::from(errno).raw_os_error() == Some(libc::EEXIST) =>
        {
            // Page already populated by another fault on the same address.
            ServeOutcome::Served
        }
        Err(e) => {
            log::error!("uffd-internal: UFFDIO_COPY failed at {page_addr:#x}: {e:?}");
            ServeOutcome::FailedTransient
        }
    }
}

fn unregister_range(uffd: &Uffd, start: *mut libc::c_void, end: *mut libc::c_void, page_size: usize) {
    let start_usz = start as usize;
    let end_usz = end as usize;
    if end_usz <= start_usz {
        return;
    }
    if !start_usz.is_multiple_of(page_size) || !end_usz.is_multiple_of(page_size) {
        log::warn!(
            "uffd-internal: REMOVE range not page-aligned start={start_usz:#x} end={end_usz:#x}"
        );
        return;
    }
    let len = end_usz - start_usz;
    if let Err(e) = uffd.unregister(start, len) {
        log::warn!("uffd-internal: UFFDIO_UNREGISTER failed start={start:?} len={len}: {e:?}");
    }
}

/// Records each unique page-fault offset in first-touch order by appending a line to
/// the target file as each new offset is observed.
///
/// The file is opened up front and held for the recorder's lifetime; the kernel page
/// cache absorbs the per-fault writes and the periodic dirty-pages writeback eventually
/// reaches disk without requiring an explicit flush at shutdown. A SIGKILL'd Firecracker
/// loses at most the last few unwritten-back entries; [`load_prefetch_offsets`] is
/// robust to truncation, so the next restore replays a valid prefix with degraded
/// prefetch coverage and no incorrect behavior.
#[derive(Debug)]
struct Recorder {
    seen: HashSet<u64>,
    file: std::fs::File,
}

impl Recorder {
    fn create(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            seen: HashSet::new(),
            file: std::fs::File::create(path)?,
        })
    }

    /// Returns true when `offset` was newly inserted (and a line was appended), false
    /// when it was already present.
    fn record(&mut self, offset: u64) -> bool {
        if self.seen.insert(offset) {
            // Best-effort write: a failed append degrades prefetch coverage on the
            // next restore but is not a VM-correctness concern.
            let _ = writeln!(self.file, "{offset}");
            true
        } else {
            false
        }
    }
}

/// Parse an access log: one decimal u64 per line, blank lines and lines starting with
/// `#` skipped, misaligned offsets dropped with a warning. Returns the offsets in file
/// order so prefetch replays first-touch sequence.
fn load_prefetch_offsets(path: &Path, page_size: usize) -> Vec<u64> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            log::warn!("uffd-internal: cannot open access log {path:?}: {e}");
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let page_mask = (page_size as u64) - 1;
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let off: u64 = match trimmed.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if off & page_mask != 0 {
            log::warn!("uffd-internal: skipping misaligned access-log offset {off}");
            continue;
        }
        if seen.insert(off) {
            out.push(off);
        }
    }
    out
}

/// Build a [`Config`] from raw path references.
pub fn config_from_paths(
    snapshot_path: &Path,
    base_path: Option<&Path>,
    access_log_path: Option<&Path>,
    record_to: Option<&Path>,
    abort_on_handler_death: bool,
) -> Config {
    Config {
        snapshot_path: snapshot_path.to_path_buf(),
        base_path: base_path.map(Path::to_path_buf),
        access_log_path: access_log_path.map(Path::to_path_buf),
        record_to: record_to.map(Path::to_path_buf),
        abort_on_handler_death,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_bitmap_set_and_query() {
        let mut pm = PresenceBitmap::with_pages(130);
        for i in 0..130 {
            assert!(!pm.is_set(i));
        }
        pm.set(0);
        pm.set(65);
        pm.set(129);
        assert!(pm.is_set(0) && pm.is_set(65) && pm.is_set(129));
        assert!(!pm.is_set(1) && !pm.is_set(64) && !pm.is_set(128));
    }

    #[test]
    fn scan_present_pages_marks_data_pages_not_holes() {
        use std::io::{Seek, SeekFrom, Write};
        let ps = 4096usize;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mem.diff");
        let mut f = std::fs::File::create(&path).unwrap();
        f.set_len((4 * ps) as u64).unwrap(); // 4 pages, all holes
        // Real (non-zero) data into pages 0 and 2; leave 1 and 3 as holes — exactly
        // how dump_dirty lays out a diff (dirty = extent, clean = hole).
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&vec![1u8; ps]).unwrap();
        f.seek(SeekFrom::Start((2 * ps) as u64)).unwrap();
        f.write_all(&vec![2u8; ps]).unwrap();
        f.sync_all().unwrap();
        drop(f);

        let pm = scan_present_pages(&path, ps).unwrap();
        assert!(pm.is_set(0), "page 0 has data");
        assert!(!pm.is_set(1), "page 1 is a hole → must fall through to base");
        assert!(pm.is_set(2), "page 2 has data");
        assert!(!pm.is_set(3), "page 3 is a hole → must fall through to base");
    }

    #[test]
    fn presence_sidecar_roundtrip_matches_scan() {
        use std::io::{Seek, SeekFrom, Write};
        let ps = 4096usize;
        let npages = 4usize;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mem.diff");
        let mut f = std::fs::File::create(&path).unwrap();
        f.set_len((npages * ps) as u64).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&vec![1u8; ps]).unwrap();
        f.seek(SeekFrom::Start((2 * ps) as u64)).unwrap();
        f.write_all(&vec![2u8; ps]).unwrap();
        f.sync_all().unwrap();
        drop(f);

        let scanned = scan_present_pages(&path, ps).unwrap();
        write_presence_bitmap(&path, ps, npages, &scanned.bits).unwrap();
        let pm = read_presence_sidecar(&path, ps, npages).unwrap().unwrap();
        assert_eq!(pm.bits, scanned.bits);
        assert!(pm.is_set(0) && pm.is_set(2));
        assert!(!pm.is_set(1) && !pm.is_set(3));

        // Word-count mismatches are rejected at write time.
        assert!(write_presence_bitmap(&path, ps, npages, &[0u64; 2]).is_err());
    }

    #[test]
    fn presence_sidecar_missing_is_none_invalid_is_error() {
        let ps = 4096usize;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mem.diff");
        std::fs::write(&path, vec![1u8; 2 * ps]).unwrap();

        // No side-car ⇒ fall back to scanning (pre-side-car snapshots).
        assert!(read_presence_sidecar(&path, ps, 2).unwrap().is_none());

        // 0-byte side-car is the torn-save sentinel ⇒ hard error carrying the
        // exact "(torn snapshot save)" marker orchestrators classify on.
        std::fs::write(presence_sidecar_path(&path), []).unwrap();
        match read_presence_sidecar(&path, ps, 2) {
            Err(InternalUffdError::LayeredInvalid(msg)) => {
                assert!(msg.contains("(torn snapshot save)"), "message was: {msg}");
            }
            other => panic!("expected LayeredInvalid, got {other:?}"),
        }

        // The 1-byte marker means the save couldn't derive presence ⇒ a distinct
        // hard error that does NOT read as a torn save.
        std::fs::write(presence_sidecar_path(&path), [PRESENCE_UNDERIVABLE]).unwrap();
        match read_presence_sidecar(&path, ps, 2) {
            Err(InternalUffdError::LayeredInvalid(msg)) => {
                assert!(!msg.contains("(torn snapshot save)"), "message was: {msg}");
                assert!(msg.contains("un-layerable"), "message was: {msg}");
            }
            other => panic!("expected LayeredInvalid, got {other:?}"),
        }

        // A valid side-car for a *different* geometry ⇒ hard error, never a scan
        // fallback (the bitmap doesn't describe this overlay).
        let scanned = scan_present_pages(&path, ps).unwrap();
        write_presence_bitmap(&path, ps, 2, &scanned.bits).unwrap();
        assert!(read_presence_sidecar(&path, ps, 2).unwrap().is_some());
        assert!(matches!(
            read_presence_sidecar(&path, ps, 3),
            Err(InternalUffdError::LayeredInvalid(_))
        ));
        assert!(matches!(
            read_presence_sidecar(&path, 2 * ps, 1),
            Err(InternalUffdError::LayeredInvalid(_))
        ));

        // Garbage header ⇒ hard error.
        std::fs::write(presence_sidecar_path(&path), vec![0u8; 64]).unwrap();
        assert!(matches!(
            read_presence_sidecar(&path, ps, 2),
            Err(InternalUffdError::LayeredInvalid(_))
        ));

        // A single flipped bit anywhere in a valid side-car fails the checksum —
        // without it, one flipped word silently mis-layers 64 pages.
        let scanned = scan_present_pages(&path, ps).unwrap();
        write_presence_bitmap(&path, ps, 2, &scanned.bits).unwrap();
        let mut bytes = std::fs::read(presence_sidecar_path(&path)).unwrap();
        bytes[PRESENCE_HEADER_LEN] ^= 0x01;
        std::fs::write(presence_sidecar_path(&path), &bytes).unwrap();
        match read_presence_sidecar(&path, ps, 2) {
            Err(InternalUffdError::LayeredInvalid(msg)) => {
                assert!(msg.contains("checksum"), "message was: {msg}");
            }
            other => panic!("expected LayeredInvalid, got {other:?}"),
        }
    }

    #[test]
    fn presence_sidecar_survives_extent_rewrite() {
        use std::io::{Seek, SeekFrom, Write};
        let ps = 4096usize;
        let npages = 4usize;
        let dir = tempfile::tempdir().unwrap();

        // Base: every page 0xBB.
        let base_path = dir.path().join("mem.base");
        std::fs::write(&base_path, vec![0xBBu8; npages * ps]).unwrap();

        // Overlay as dump_dirty lays it out: page 1 dirtied to 0xAA, page 2 dirtied
        // to ZEROS (written extent — a freshly zeroed guest page), pages 0/3 clean holes.
        let ov_path = dir.path().join("mem.diff");
        let mut f = std::fs::File::create(&ov_path).unwrap();
        f.set_len((npages * ps) as u64).unwrap();
        f.seek(SeekFrom::Start(ps as u64)).unwrap();
        f.write_all(&vec![0xAAu8; ps]).unwrap();
        f.seek(SeekFrom::Start((2 * ps) as u64)).unwrap();
        f.write_all(&vec![0u8; ps]).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let scanned = scan_present_pages(&ov_path, ps).unwrap();
        write_presence_bitmap(&ov_path, ps, npages, &scanned.bits).unwrap();

        // Rewrite the overlay the way a zero-eliding transfer would: identical bytes,
        // but the written-zero page 2 becomes a hole. Byte-level verification (hashes)
        // cannot distinguish the two files.
        let mut f = std::fs::File::create(&ov_path).unwrap();
        f.set_len((npages * ps) as u64).unwrap();
        f.seek(SeekFrom::Start(ps as u64)).unwrap();
        f.write_all(&vec![0xAAu8; ps]).unwrap();
        f.sync_all().unwrap();
        drop(f);

        // The scan now mistakes page 2 for clean and would serve the base's stale
        // 0xBB where the guest wrote zeros — the corruption this side-car prevents.
        let scanned = scan_present_pages(&ov_path, ps).unwrap();
        assert!(!scanned.is_set(2), "extent rewrite made page 2 look clean");

        let pm = read_presence_sidecar(&ov_path, ps, npages).unwrap().unwrap();
        assert!(pm.is_set(1) && pm.is_set(2));
        assert!(!pm.is_set(0) && !pm.is_set(3));

        let backing = Backing {
            overlay: mmap_snapshot(&ov_path).unwrap(),
            base: Some(mmap_snapshot(&base_path).unwrap()),
            present: Some(pm),
            page_size: ps,
        };
        let read = |pg: usize| -> u8 {
            let p = backing.src_ptr((pg * ps) as u64);
            // SAFETY: `p` points at a mapped, readable page of `ps` bytes.
            unsafe { *p }
        };
        assert_eq!(read(0), 0xBB, "clean page 0 from base");
        assert_eq!(read(1), 0xAA, "dirty page 1 from overlay");
        assert_eq!(read(2), 0x00, "dirtied-to-zero page 2 must stay overlay zeros");
        assert_eq!(read(3), 0xBB, "clean page 3 from base");
    }

    #[test]
    fn layered_src_ptr_serves_overlay_when_present_else_base() {
        use std::io::{Seek, SeekFrom, Write};
        let ps = 4096usize;
        let npages = 4usize;
        let dir = tempfile::tempdir().unwrap();

        // Base: a complete image, every page filled with 0xBB.
        let base_path = dir.path().join("mem.base");
        std::fs::write(&base_path, vec![0xBBu8; npages * ps]).unwrap();

        // Overlay: full-size sparse file with only page 1 written (0xAA); the rest are
        // holes — exactly the on-disk shape of a layered diff over the base above.
        let ov_path = dir.path().join("mem.diff");
        let mut f = std::fs::File::create(&ov_path).unwrap();
        f.set_len((npages * ps) as u64).unwrap();
        f.seek(SeekFrom::Start(ps as u64)).unwrap();
        f.write_all(&vec![0xAAu8; ps]).unwrap();
        f.sync_all().unwrap();
        drop(f);

        let present = scan_present_pages(&ov_path, ps).unwrap();
        let backing = Backing {
            overlay: mmap_snapshot(&ov_path).unwrap(),
            base: Some(mmap_snapshot(&base_path).unwrap()),
            present: Some(present),
            page_size: ps,
        };

        // The resolution that, if wrong, silently corrupts guest memory: a present page
        // must come from the overlay; a hole must fall through to the base (serving it
        // from the overlay would read it as a zero hole, not the base's real bytes).
        let read = |pg: usize| -> u8 {
            let p = backing.src_ptr((pg * ps) as u64);
            // SAFETY: `p` points at a mapped, readable page of `ps` bytes.
            unsafe { *p }
        };
        assert_eq!(read(0), 0xBB, "hole page 0 must come from base");
        assert_eq!(read(1), 0xAA, "present page 1 must come from overlay");
        assert_eq!(read(2), 0xBB, "hole page 2 must come from base");
        assert_eq!(read(3), 0xBB, "hole page 3 must come from base");
    }

    #[test]
    fn monolithic_src_ptr_always_serves_overlay() {
        let ps = 4096usize;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mem.snap");
        std::fs::write(&path, vec![0x5Au8; 2 * ps]).unwrap();
        // No base/present ⇒ single-file (monolithic) restore: every page from overlay.
        // This is the backward-compat path — the layered loader is its superset.
        let backing = Backing {
            overlay: mmap_snapshot(&path).unwrap(),
            base: None,
            present: None,
            page_size: ps,
        };
        for pg in 0..2 {
            let p = backing.src_ptr((pg * ps) as u64);
            // SAFETY: `p` points at a mapped, readable page of `ps` bytes.
            assert_eq!(unsafe { *p }, 0x5A);
        }
    }

    #[test]
    fn validate_layered_rejects_bad_preconditions() {
        let ps = 4096usize;
        let total = (4 * ps) as u64; // 4 pages of guest RAM
        let bad = |r: Result<(), InternalUffdError>| matches!(r, Err(InternalUffdError::LayeredInvalid(_)));

        // Happy path: both layers cover RAM, host-page granularity, small blocks.
        assert!(validate_layered(4 * ps, 4 * ps, total, ps, ps, Some(ps as u64)).is_ok());

        // Overlay too small.
        assert!(bad(validate_layered(2 * ps, 4 * ps, total, ps, ps, Some(ps as u64))));
        // Base too small.
        assert!(bad(validate_layered(4 * ps, 2 * ps, total, ps, ps, Some(ps as u64))));
        // Huge-page guest (page_size > host page size) — would serve clean sub-pages as zeros.
        assert!(bad(validate_layered(
            4 * ps,
            4 * ps,
            total,
            2 * 1024 * 1024,
            ps,
            Some(ps as u64)
        )));
        // Sub-host page size (e.g. default 4096 on a 16K-page host) — would misindex
        // the presence bitmap and misalign UFFDIO_COPY.
        assert!(bad(validate_layered(
            4 * ps,
            4 * ps,
            total,
            ps,
            4 * ps,
            Some(ps as u64)
        )));
        // Filesystem block size larger than the page — scanned holes wouldn't be
        // page-granular. With an explicit side-car (None) the same block size is fine.
        assert!(bad(validate_layered(4 * ps, 4 * ps, total, ps, ps, Some((ps * 16) as u64))));
        assert!(validate_layered(4 * ps, 4 * ps, total, ps, ps, None).is_ok());
    }

    #[test]
    fn serve_pagefault_copies_overlay_when_present_else_base() {
        use std::io::{Seek, SeekFrom, Write};
        let ps = 4096usize;
        let npages = 4usize;
        let total = npages * ps;

        // A user-mode-only uffd needs no privileges for self-registered anon memory, but
        // some kernels gate even that (vm.unprivileged_userfaultfd=0). Skip if unavailable
        // rather than fail spuriously — this still exercises the real copy path where it can.
        let uffd = match UffdBuilder::new().close_on_exec(true).user_mode_only(true).create() {
            Ok(u) => u,
            Err(e) => {
                eprintln!("skipping serve_pagefault test: userfaultfd unavailable: {e:?}");
                return;
            }
        };

        // "Guest memory": an anon region registered MISSING so the first touch faults.
        // SAFETY: standard anonymous mmap of `total` bytes; checked against MAP_FAILED.
        let mem = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mem, libc::MAP_FAILED, "mmap guest region");
        uffd.register(mem, total).expect("register region");

        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("mem.base");
        std::fs::write(&base_path, vec![0xBBu8; total]).unwrap();
        let ov_path = dir.path().join("mem.diff");
        let mut f = std::fs::File::create(&ov_path).unwrap();
        f.set_len(total as u64).unwrap();
        f.seek(SeekFrom::Start(ps as u64)).unwrap(); // page 1 only
        f.write_all(&vec![0xAAu8; ps]).unwrap();
        f.sync_all().unwrap();
        drop(f);

        let backing = Backing {
            overlay: mmap_snapshot(&ov_path).unwrap(),
            base: Some(mmap_snapshot(&base_path).unwrap()),
            present: Some(scan_present_pages(&ov_path, ps).unwrap()),
            page_size: ps,
        };
        #[allow(deprecated)]
        let mappings = vec![GuestRegionUffdMapping {
            base_host_virt_addr: mem as u64,
            size: total,
            offset: 0,
            page_size: ps,
            page_size_kib: ps,
        }];

        // Serve each page through the real UFFDIO_COPY path, then read the now-installed
        // guest page back: present page from the overlay (0xAA), holes from base (0xBB).
        for pg in 0..npages {
            let addr = mem as u64 + (pg * ps) as u64;
            assert_eq!(
                serve_pagefault(&uffd, &mappings, &backing, ps, addr),
                ServeOutcome::Served,
                "serve page {pg}"
            );
            // SAFETY: the page at `addr` was just installed by UFFDIO_COPY.
            let got = unsafe { *(addr as *const u8) };
            let want = if pg == 1 { 0xAA } else { 0xBB };
            assert_eq!(got, want, "page {pg}");
        }

        // SAFETY: unmap the region we mapped above.
        unsafe { libc::munmap(mem, total) };
    }

    #[test]
    fn recorder_writes_one_line_per_unique_offset_in_first_touch_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let mut r = Recorder::create(&path).unwrap();
        assert!(r.record(4096));
        assert!(r.record(8192));
        assert!(!r.record(4096));
        assert!(r.record(12288));
        assert!(!r.record(8192));
        // Drop the recorder so the writes are visible (the File's buffer is flushed
        // by Drop and the kernel exposes the writes to subsequent reads).
        drop(r);
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "4096\n8192\n12288\n");
    }

    #[test]
    fn recorder_create_fails_on_unwritable_path() {
        Recorder::create(Path::new("/nonexistent/dir/access.log")).unwrap_err();
    }

    #[test]
    fn load_prefetch_offsets_skips_blank_comment_and_misaligned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        std::fs::write(
            &path,
            "# header comment\n\n0\n4096\n4097\n8192\n4096\nnot-a-number\n12288\n",
        )
        .unwrap();
        let offsets = load_prefetch_offsets(&path, 4096);
        assert_eq!(offsets, vec![0, 4096, 8192, 12288]);
    }

    #[test]
    fn load_prefetch_offsets_returns_empty_when_file_missing() {
        let path = Path::new("/nonexistent/path/that/does/not/exist.log");
        assert!(load_prefetch_offsets(path, 4096).is_empty());
    }

    #[test]
    fn record_fault_skips_when_recorder_is_none() {
        // The "no recorder" branch is the hot path on normal restores; a no-op call must
        // not panic even when the mappings table is empty.
        let stats = Stats::default();
        record_fault(None, &[], 4096, 0x1000, &stats);
        assert_eq!(stats.recorded_offsets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn record_fault_writes_file_offset_for_in_range_addr() {
        #[allow(deprecated)]
        let mappings = vec![GuestRegionUffdMapping {
            base_host_virt_addr: 0x1000_0000,
            size: 0x4000,
            offset: 0x2000,
            page_size: 4096,
            page_size_kib: 4096,
        }];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let mut rec = Recorder::create(&path).unwrap();
        let stats = Stats::default();
        // Fault at virt 0x1000_1000 → page-aligned to itself → in-region offset 0x1000
        // → file offset 0x2000 + 0x1000 = 0x3000.
        record_fault(Some(&mut rec), &mappings, 4096, 0x1000_1000, &stats);
        drop(rec);
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "12288\n"); // 0x3000
        assert_eq!(stats.recorded_offsets.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn record_fault_drops_addr_outside_any_region() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let mut rec = Recorder::create(&path).unwrap();
        let stats = Stats::default();
        record_fault(Some(&mut rec), &[], 4096, 0x1000, &stats);
        drop(rec);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        assert_eq!(stats.recorded_offsets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn record_fault_counter_only_increments_on_new_offsets() {
        #[allow(deprecated)]
        let mappings = vec![GuestRegionUffdMapping {
            base_host_virt_addr: 0x1000_0000,
            size: 0x4000,
            offset: 0,
            page_size: 4096,
            page_size_kib: 4096,
        }];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let mut rec = Recorder::create(&path).unwrap();
        let stats = Stats::default();
        record_fault(Some(&mut rec), &mappings, 4096, 0x1000_0000, &stats);
        record_fault(Some(&mut rec), &mappings, 4096, 0x1000_0000, &stats);
        record_fault(Some(&mut rec), &mappings, 4096, 0x1000_1000, &stats);
        assert_eq!(stats.recorded_offsets.load(Ordering::Relaxed), 2);
    }
}
