// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;
use std::cmp;
use std::io::Write;
use std::result::Result;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

use ::timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};

use ::logger::{error, IncMetric, METRICS};
use ::utils::eventfd::EventFd;
use ::virtio_gen::virtio_blk::*;
use ::vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

use super::*;
use super::{
    super::{ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_BALLOON},
    utils::{compact_page_frame_numbers, remove_range},
    BALLOON_DEV_ID,
};

use crate::virtio::balloon::Error as BalloonError;
use crate::virtio::{IrqTrigger, IrqType};

const SIZE_OF_U32: usize = std::mem::size_of::<u32>();
const SIZE_OF_STAT: usize = std::mem::size_of::<BalloonStat>();

fn mib_to_pages(amount_mib: u32) -> Result<u32, BalloonError> {
    amount_mib
        .checked_mul(MIB_TO_4K_PAGES)
        .ok_or(BalloonError::TooManyPagesRequested)
}

fn pages_to_mib(amount_pages: u32) -> u32 {
    amount_pages / MIB_TO_4K_PAGES
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct ConfigSpace {
    pub num_pages: u32,
    pub actual_pages: u32,
}

// Safe because ConfigSpace only contains plain data.
unsafe impl ByteValued for ConfigSpace {}

// This structure needs the `packed` attribute, otherwise Rust will assume
// the size to be 16 bytes.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct BalloonStat {
    pub tag: u16,
    pub val: u64,
}

// Safe because BalloonStat only contains plain data.
unsafe impl ByteValued for BalloonStat {}

// BalloonStats holds statistics returned from the stats_queue.
#[derive(Clone, Default, Debug, PartialEq, Serialize)]
pub struct BalloonConfig {
    pub amount_mib: u32,
    pub deflate_on_oom: bool,
    pub stats_polling_interval_s: u16,
}

// BalloonStats holds statistics returned from the stats_queue.
#[derive(Clone, Default, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BalloonStats {
    pub target_pages: u32,
    pub actual_pages: u32,
    pub target_mib: u32,
    pub actual_mib: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_out: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub major_faults: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minor_faults: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_memory: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_memory: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_memory: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_caches: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hugetlb_allocations: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hugetlb_failures: Option<u64>,
}

impl BalloonStats {
    fn update_with_stat(&mut self, stat: &BalloonStat) -> Result<(), BalloonError> {
        let val = Some(stat.val);
        match stat.tag {
            VIRTIO_BALLOON_S_SWAP_IN => self.swap_in = val,
            VIRTIO_BALLOON_S_SWAP_OUT => self.swap_out = val,
            VIRTIO_BALLOON_S_MAJFLT => self.major_faults = val,
            VIRTIO_BALLOON_S_MINFLT => self.minor_faults = val,
            VIRTIO_BALLOON_S_MEMFREE => self.free_memory = val,
            VIRTIO_BALLOON_S_MEMTOT => self.total_memory = val,
            VIRTIO_BALLOON_S_AVAIL => self.available_memory = val,
            VIRTIO_BALLOON_S_CACHES => self.disk_caches = val,
            VIRTIO_BALLOON_S_HTLB_PGALLOC => self.hugetlb_allocations = val,
            VIRTIO_BALLOON_S_HTLB_PGFAIL => self.hugetlb_failures = val,
            _ => {
                return Err(BalloonError::MalformedPayload);
            }
        }

        Ok(())
    }
}

// Virtio balloon device.
pub struct Balloon {
    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) config_space: ConfigSpace,
    pub(crate) activate_evt: EventFd,

    // Transport related fields.
    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: [EventFd; NUM_QUEUES],
    pub(crate) device_state: DeviceState,
    pub(crate) irq_trigger: IrqTrigger,

    // Implementation specific fields.
    pub(crate) restored: bool,
    pub(crate) stats_polling_interval_s: u16,
    pub(crate) stats_timer: TimerFd,
    // The index of the previous stats descriptor is saved because
    // it is acknowledged after the stats queue is processed.
    pub(crate) stats_desc_index: Option<u16>,
    pub(crate) latest_stats: BalloonStats,
    // A buffer used as pfn accumulator during descriptor processing.
    pub(crate) pfn_buffer: [u32; MAX_PAGE_COMPACT_BUFFER],
}

impl Balloon {
    pub fn new(
        amount_mib: u32,
        deflate_on_oom: bool,
        stats_polling_interval_s: u16,
        restored: bool,
    ) -> Result<Balloon, BalloonError> {
        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;

        if deflate_on_oom {
            avail_features |= 1u64 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM;
        };

        if stats_polling_interval_s > 0 {
            avail_features |= 1u64 << VIRTIO_BALLOON_F_STATS_VQ;
        }

        let queue_evts = [
            EventFd::new(libc::EFD_NONBLOCK).map_err(BalloonError::EventFd)?,
            EventFd::new(libc::EFD_NONBLOCK).map_err(BalloonError::EventFd)?,
            EventFd::new(libc::EFD_NONBLOCK).map_err(BalloonError::EventFd)?,
        ];

        let mut queues: Vec<Queue> = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        // The VirtIO specification states that the statistics queue should
        // not be present at all if the statistics are not enabled.
        if stats_polling_interval_s == 0 {
            let _ = queues.remove(STATS_INDEX);
        }

        let stats_timer =
            TimerFd::new_custom(ClockId::Monotonic, true, true).map_err(BalloonError::Timer)?;

        Ok(Balloon {
            avail_features,
            acked_features: 0u64,
            config_space: ConfigSpace {
                num_pages: mib_to_pages(amount_mib)?,
                actual_pages: 0,
            },
            queue_evts,
            queues,
            irq_trigger: IrqTrigger::new().map_err(BalloonError::EventFd)?,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(BalloonError::EventFd)?,
            restored,
            stats_polling_interval_s,
            stats_timer,
            stats_desc_index: None,
            latest_stats: BalloonStats::default(),
            pfn_buffer: [0u32; MAX_PAGE_COMPACT_BUFFER],
        })
    }

    pub(crate) fn process_inflate_queue_event(&mut self) -> Result<(), BalloonError> {
        self.queue_evts[INFLATE_INDEX]
            .read()
            .map_err(BalloonError::EventFd)?;
        self.process_inflate()
    }

    pub(crate) fn process_deflate_queue_event(&mut self) -> Result<(), BalloonError> {
        self.queue_evts[DEFLATE_INDEX]
            .read()
            .map_err(BalloonError::EventFd)?;
        self.process_deflate_queue()
    }

    pub(crate) fn process_stats_queue_event(&mut self) -> Result<(), BalloonError> {
        self.queue_evts[STATS_INDEX]
            .read()
            .map_err(BalloonError::EventFd)?;
        self.process_stats_queue()
    }

    pub(crate) fn process_stats_timer_event(&mut self) -> Result<(), BalloonError> {
        self.stats_timer.read();
        self.trigger_stats_update()
    }

    pub(crate) fn process_inflate(&mut self) -> Result<(), BalloonError> {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();
        METRICS.balloon.inflate_count.inc();

        let queue = &mut self.queues[INFLATE_INDEX];
        // The pfn buffer index used during descriptor processing.
        let mut pfn_buffer_idx = 0;
        let mut needs_interrupt = false;
        let mut valid_descs_found = true;

        // Loop until there are no more valid DescriptorChains.
        while valid_descs_found {
            valid_descs_found = false;
            // Internal loop processes descriptors and acummulates the pfns in `pfn_buffer`.
            // Breaks out when there is not enough space in `pfn_buffer` to completely process
            // the next descriptor.
            while let Some(head) = queue.pop(mem) {
                let len = head.len as usize;
                let max_len = MAX_PAGES_IN_DESC * SIZE_OF_U32;
                valid_descs_found = true;

                if !head.is_write_only() && len % SIZE_OF_U32 == 0 {
                    // Check descriptor pfn count.
                    if len > max_len {
                        error!(
                            "Inflate descriptor has bogus page count {} > {}, skipping.",
                            len as usize / SIZE_OF_U32,
                            MAX_PAGES_IN_DESC
                        );

                        // Skip descriptor.
                        continue;
                    }
                    // Break loop if `pfn_buffer` will be overrun by adding all pfns from current desc.
                    if MAX_PAGE_COMPACT_BUFFER - pfn_buffer_idx < len as usize / SIZE_OF_U32 {
                        queue.undo_pop();
                        break;
                    }

                    // This is safe, `len` was validated above.
                    for index in (0..len).step_by(SIZE_OF_U32) {
                        let addr = head
                            .addr
                            .checked_add(index as u64)
                            .ok_or(BalloonError::MalformedDescriptor)?;

                        let page_frame_number = mem
                            .read_obj::<u32>(addr)
                            .map_err(|_| BalloonError::MalformedDescriptor)?;

                        self.pfn_buffer[pfn_buffer_idx] = page_frame_number;
                        pfn_buffer_idx += 1;
                    }
                }

                // Acknowledge the receipt of the descriptor.
                // 0 is number of bytes the device has written to memory.
                queue
                    .add_used(mem, head.index, 0)
                    .map_err(BalloonError::Queue)?;
                needs_interrupt = true;
            }

            // Compact pages into ranges.
            let page_ranges = compact_page_frame_numbers(&mut self.pfn_buffer[..pfn_buffer_idx]);
            pfn_buffer_idx = 0;

            // Remove the page ranges.
            for (page_frame_number, range_len) in page_ranges {
                let guest_addr =
                    GuestAddress((page_frame_number as u64) << VIRTIO_BALLOON_PFN_SHIFT);

                if let Err(e) = remove_range(
                    mem,
                    (guest_addr, u64::from(range_len) << VIRTIO_BALLOON_PFN_SHIFT),
                    self.restored,
                ) {
                    error!("Error removing memory range: {:?}", e);
                }
            }
        }

        if needs_interrupt {
            self.signal_used_queue()?;
        }

        Ok(())
    }

    pub(crate) fn process_deflate_queue(&mut self) -> Result<(), BalloonError> {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();
        METRICS.balloon.deflate_count.inc();

        let queue = &mut self.queues[DEFLATE_INDEX];
        let mut needs_interrupt = false;

        while let Some(head) = queue.pop(mem) {
            queue
                .add_used(mem, head.index, 0)
                .map_err(BalloonError::Queue)?;
            needs_interrupt = true;
        }

        if needs_interrupt {
            self.signal_used_queue()
        } else {
            Ok(())
        }
    }

    pub(crate) fn process_stats_queue(&mut self) -> std::result::Result<(), BalloonError> {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();
        METRICS.balloon.stats_updates_count.inc();

        while let Some(head) = self.queues[STATS_INDEX].pop(mem) {
            if let Some(prev_stats_desc) = self.stats_desc_index {
                // We shouldn't ever have an extra buffer if the driver follows
                // the protocol, but return it if we find one.
                error!("balloon: driver is not compliant, more than one stats buffer received");
                self.queues[STATS_INDEX]
                    .add_used(mem, prev_stats_desc, 0)
                    .map_err(BalloonError::Queue)?;
            }
            for index in (0..head.len).step_by(SIZE_OF_STAT) {
                // Read the address at position `index`. The only case
                // in which this fails is if there is overflow,
                // in which case this descriptor is malformed,
                // so we ignore the rest of it.
                let addr = head
                    .addr
                    .checked_add(index as u64)
                    .ok_or(BalloonError::MalformedDescriptor)?;
                let stat = mem
                    .read_obj::<BalloonStat>(addr)
                    .map_err(|_| BalloonError::MalformedDescriptor)?;
                self.latest_stats.update_with_stat(&stat).map_err(|_| {
                    METRICS.balloon.stats_update_fails.inc();
                    BalloonError::MalformedPayload
                })?;
            }

            self.stats_desc_index = Some(head.index);
        }

        Ok(())
    }

    pub(crate) fn signal_used_queue(&self) -> Result<(), BalloonError> {
        self.irq_trigger.trigger_irq(IrqType::Vring).map_err(|e| {
            METRICS.balloon.event_fails.inc();
            BalloonError::InterruptError(e)
        })
    }

    /// Process device virtio queue(s).
    pub fn process_virtio_queues(&mut self) {
        let _ = self.process_inflate();
        let _ = self.process_deflate_queue();
    }

    pub fn id(&self) -> &str {
        BALLOON_DEV_ID
    }

    fn trigger_stats_update(&mut self) -> Result<(), BalloonError> {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();

        // The communication is driven by the device by using the buffer
        // and sending a used buffer notification
        if let Some(index) = self.stats_desc_index.take() {
            self.queues[STATS_INDEX]
                .add_used(mem, index, 0)
                .map_err(BalloonError::Queue)?;
            self.signal_used_queue()
        } else {
            error!("Failed to update balloon stats, missing descriptor.");
            Ok(())
        }
    }

    pub fn update_size(&mut self, amount_mib: u32) -> Result<(), BalloonError> {
        if self.is_activated() {
            self.config_space.num_pages = mib_to_pages(amount_mib)?;
            self.irq_trigger
                .trigger_irq(IrqType::Config)
                .map_err(BalloonError::InterruptError)
        } else {
            Err(BalloonError::DeviceNotActive)
        }
    }

    pub fn update_stats_polling_interval(&mut self, interval_s: u16) -> Result<(), BalloonError> {
        if self.stats_polling_interval_s == interval_s {
            return Ok(());
        }

        if self.stats_polling_interval_s == 0 || interval_s == 0 {
            return Err(BalloonError::StatisticsStateChange);
        }

        self.trigger_stats_update()?;

        self.stats_polling_interval_s = interval_s;
        self.update_timer_state();
        Ok(())
    }

    pub fn update_timer_state(&mut self) {
        let timer_state = TimerState::Periodic {
            current: Duration::from_secs(self.stats_polling_interval_s as u64),
            interval: Duration::from_secs(self.stats_polling_interval_s as u64),
        };
        self.stats_timer
            .set_state(timer_state, SetTimeFlags::Default);
    }

    pub fn num_pages(&self) -> u32 {
        self.config_space.num_pages
    }

    pub fn size_mb(&self) -> u32 {
        pages_to_mib(self.config_space.num_pages)
    }

    pub fn deflate_on_oom(&self) -> bool {
        self.avail_features & (1u64 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM) != 0
    }

    pub fn stats_polling_interval_s(&self) -> u16 {
        self.stats_polling_interval_s
    }

    pub fn latest_stats(&mut self) -> Option<&BalloonStats> {
        if self.stats_enabled() {
            self.latest_stats.target_pages = self.config_space.num_pages;
            self.latest_stats.actual_pages = self.config_space.actual_pages;
            self.latest_stats.target_mib = pages_to_mib(self.latest_stats.target_pages);
            self.latest_stats.actual_mib = pages_to_mib(self.latest_stats.actual_pages);
            Some(&self.latest_stats)
        } else {
            None
        }
    }

    pub fn config(&self) -> BalloonConfig {
        BalloonConfig {
            amount_mib: self.size_mb(),
            deflate_on_oom: self.deflate_on_oom(),
            stats_polling_interval_s: self.stats_polling_interval_s(),
        }
    }

    pub(crate) fn stats_enabled(&self) -> bool {
        self.stats_polling_interval_s > 0
    }

    pub(crate) fn set_stats_desc_index(&mut self, stats_desc_index: Option<u16>) {
        self.stats_desc_index = stats_desc_index;
    }
}

impl VirtioDevice for Balloon {
    fn device_type(&self) -> u32 {
        TYPE_BALLOON
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_evt(&self) -> &EventFd {
        &self.irq_trigger.irq_evt
    }

    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.irq_trigger.irq_status.clone()
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_space_bytes = self.config_space.as_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }

        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(
                &config_space_bytes[offset as usize..cmp::min(end, config_len) as usize],
            )
            .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_space_bytes = self.config_space.as_mut_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }
        config_space_bytes[offset as usize..(offset + data_len) as usize].copy_from_slice(data);
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        self.device_state = DeviceState::Activated(mem);
        if self.activate_evt.write(1).is_err() {
            error!("Balloon: Cannot write to activate_evt");
            METRICS.balloon.activate_fails.inc();
            self.device_state = DeviceState::Inactive;
            return Err(super::super::ActivateError::BadActivate);
        }

        if self.stats_enabled() {
            self.update_timer_state();
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::u32;

    use super::super::CONFIG_SPACE_SIZE;
    use super::*;
    use crate::virtio::balloon::test_utils::{
        check_request_completion, invoke_handler_for_queue_event, set_request,
    };
    use crate::virtio::test_utils::{default_mem, VirtQueue};
    use crate::virtio::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::{check_metric_after_block, report_balloon_event_fail};
    use vm_memory::GuestAddress;

    impl Balloon {
        pub(crate) fn set_queue(&mut self, idx: usize, q: Queue) {
            self.queues[idx] = q;
        }

        pub(crate) fn actual_pages(&self) -> u32 {
            self.config_space.actual_pages
        }

        pub fn update_num_pages(&mut self, num_pages: u32) {
            self.config_space.num_pages = num_pages;
        }

        pub fn update_actual_pages(&mut self, actual_pages: u32) {
            self.config_space.actual_pages = actual_pages;
        }
    }

    #[test]
    fn test_balloon_stat_size() {
        assert_eq!(SIZE_OF_STAT, 10);
    }

    #[test]
    fn test_update_balloon_stats() {
        // Test all feature combinations.
        let mut stats = BalloonStats {
            target_pages: 5120,
            actual_pages: 2560,
            target_mib: 20,
            actual_mib: 10,
            swap_in: Some(0),
            swap_out: Some(0),
            major_faults: Some(0),
            minor_faults: Some(0),
            free_memory: Some(0),
            total_memory: Some(0),
            available_memory: Some(0),
            disk_caches: Some(0),
            hugetlb_allocations: Some(0),
            hugetlb_failures: Some(0),
        };

        let mut stat = BalloonStat {
            tag: VIRTIO_BALLOON_S_SWAP_IN,
            val: 1,
        };

        stats.update_with_stat(&stat).unwrap();
        assert_eq!(stats.swap_in, Some(1));
        stat.tag = VIRTIO_BALLOON_S_SWAP_OUT;
        stats.update_with_stat(&stat).unwrap();
        assert_eq!(stats.swap_out, Some(1));
        stat.tag = VIRTIO_BALLOON_S_MAJFLT;
        stats.update_with_stat(&stat).unwrap();
        assert_eq!(stats.major_faults, Some(1));
        stat.tag = VIRTIO_BALLOON_S_MINFLT;
        stats.update_with_stat(&stat).unwrap();
        assert_eq!(stats.minor_faults, Some(1));
        stat.tag = VIRTIO_BALLOON_S_MEMFREE;
        stats.update_with_stat(&stat).unwrap();
        assert_eq!(stats.free_memory, Some(1));
        stat.tag = VIRTIO_BALLOON_S_MEMTOT;
        stats.update_with_stat(&stat).unwrap();
        assert_eq!(stats.total_memory, Some(1));
        stat.tag = VIRTIO_BALLOON_S_AVAIL;
        stats.update_with_stat(&stat).unwrap();
        assert_eq!(stats.available_memory, Some(1));
        stat.tag = VIRTIO_BALLOON_S_CACHES;
        stats.update_with_stat(&stat).unwrap();
        assert_eq!(stats.disk_caches, Some(1));
        stat.tag = VIRTIO_BALLOON_S_HTLB_PGALLOC;
        stats.update_with_stat(&stat).unwrap();
        assert_eq!(stats.hugetlb_allocations, Some(1));
        stat.tag = VIRTIO_BALLOON_S_HTLB_PGFAIL;
        stats.update_with_stat(&stat).unwrap();
        assert_eq!(stats.hugetlb_failures, Some(1));
    }

    #[test]
    fn test_virtio_features() {
        // Test all feature combinations.
        for deflate_on_oom in vec![true, false].iter() {
            for stats_interval in vec![0, 1].iter() {
                let mut balloon = Balloon::new(0, *deflate_on_oom, *stats_interval, false).unwrap();
                assert_eq!(balloon.device_type(), TYPE_BALLOON);

                let features: u64 = (1u64 << VIRTIO_F_VERSION_1)
                    | ((if *deflate_on_oom { 1 } else { 0 }) << VIRTIO_BALLOON_F_DEFLATE_ON_OOM)
                    | ((*stats_interval as u64) << VIRTIO_BALLOON_F_STATS_VQ);

                assert_eq!(balloon.avail_features_by_page(0), features as u32);
                assert_eq!(balloon.avail_features_by_page(1), (features >> 32) as u32);
                for i in 2..10 {
                    assert_eq!(balloon.avail_features_by_page(i), 0u32);
                }

                for i in 0..10 {
                    balloon.ack_features_by_page(i, u32::MAX);
                }
                // Only present features should be acknowledged.
                assert_eq!(balloon.acked_features, features);
            }
        }
    }

    #[test]
    fn test_virtio_read_config() {
        let balloon = Balloon::new(0x10, true, 0, false).unwrap();

        let cfg = BalloonConfig {
            amount_mib: 16,
            deflate_on_oom: true,
            stats_polling_interval_s: 0,
        };
        assert_eq!(balloon.config(), cfg);

        let mut actual_config_space = [0u8; CONFIG_SPACE_SIZE];
        balloon.read_config(0, &mut actual_config_space);
        // The first 4 bytes are num_pages, the last 4 bytes are actual_pages.
        // The config space is little endian.
        // 0x10 MB in the constructor corresponds to 0x1000 pages in the
        // config space.
        let expected_config_space: [u8; CONFIG_SPACE_SIZE] =
            [0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(actual_config_space, expected_config_space);

        // Invalid read.
        let expected_config_space: [u8; CONFIG_SPACE_SIZE] =
            [0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf];
        actual_config_space = expected_config_space;
        balloon.read_config(CONFIG_SPACE_SIZE as u64 + 1, &mut actual_config_space);

        // Validate read failed (the config space was not updated).
        assert_eq!(actual_config_space, expected_config_space);
    }

    #[test]
    fn test_virtio_write_config() {
        let mut balloon = Balloon::new(0, true, 0, false).unwrap();

        let expected_config_space: [u8; CONFIG_SPACE_SIZE] =
            [0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        balloon.write_config(0, &expected_config_space);

        let mut actual_config_space = [0u8; CONFIG_SPACE_SIZE];
        balloon.read_config(0, &mut actual_config_space);
        assert_eq!(actual_config_space, expected_config_space);

        // Invalid write.
        let new_config_space = [0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf];
        balloon.write_config(5, &new_config_space);
        // Make sure nothing got written.
        balloon.read_config(0, &mut actual_config_space);
        assert_eq!(actual_config_space, expected_config_space);
    }

    #[test]
    fn test_invalid_request() {
        let mut balloon = Balloon::new(0, true, 0, false).unwrap();
        let mem = default_mem();
        // Only initialize the inflate queue to demonstrate invalid request handling.
        let infq = VirtQueue::new(GuestAddress(0), &mem, 16);
        balloon.set_queue(INFLATE_INDEX, infq.create_queue());
        balloon.activate(mem.clone()).unwrap();

        // Fill the second page with non-zero bytes.
        for i in 0..0x1000 {
            assert!(mem.write_obj::<u8>(1, GuestAddress((1 << 12) + i)).is_ok());
        }

        // Will write the page frame number of the affected frame at this
        // arbitrary address in memory.
        let page_addr = 0x10;

        // Invalid case: the descriptor is write-only.
        {
            mem.write_obj::<u32>(0x1, GuestAddress(page_addr)).unwrap();
            set_request(
                &infq,
                0,
                page_addr,
                SIZE_OF_U32 as u32,
                VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
            );

            invoke_handler_for_queue_event(&mut balloon, INFLATE_INDEX);
            check_request_completion(&infq, 0);

            // Check that the page was not zeroed.
            for i in 0..0x1000 {
                assert_eq!(mem.read_obj::<u8>(GuestAddress((1 << 12) + i)).unwrap(), 1);
            }
        }

        // Invalid case: descriptor len is not a multiple of 'SIZE_OF_U32'.
        {
            mem.write_obj::<u32>(0x1, GuestAddress(page_addr)).unwrap();
            set_request(
                &infq,
                1,
                page_addr,
                SIZE_OF_U32 as u32 + 1,
                VIRTQ_DESC_F_NEXT,
            );

            invoke_handler_for_queue_event(&mut balloon, INFLATE_INDEX);
            check_request_completion(&infq, 1);

            // Check that the page was not zeroed.
            for i in 0..0x1000 {
                assert_eq!(mem.read_obj::<u8>(GuestAddress((1 << 12) + i)).unwrap(), 1);
            }
        }
    }

    #[test]
    fn test_inflate() {
        let mut balloon = Balloon::new(0, true, 0, false).unwrap();
        let mem = default_mem();
        let infq = VirtQueue::new(GuestAddress(0), &mem, 16);
        balloon.set_queue(INFLATE_INDEX, infq.create_queue());
        balloon.activate(mem.clone()).unwrap();

        // Fill the third page with non-zero bytes.
        for i in 0..0x1000 {
            assert!(mem.write_obj::<u8>(1, GuestAddress((1 << 12) + i)).is_ok());
        }

        // Will write the page frame number of the affected frame at this
        // arbitrary address in memory.
        let page_addr = 0x10;

        // Error case: the request is well-formed, but we forgot
        // to trigger the inflate event queue.
        {
            mem.write_obj::<u32>(0x1, GuestAddress(page_addr)).unwrap();
            set_request(&infq, 0, page_addr, SIZE_OF_U32 as u32, VIRTQ_DESC_F_NEXT);

            check_metric_after_block!(
                METRICS.balloon.event_fails,
                1,
                balloon
                    .process_inflate_queue_event()
                    .unwrap_or_else(report_balloon_event_fail)
            );
            // Verify that nothing got processed.
            assert_eq!(infq.used.idx.get(), 0);

            // Check that the page was not zeroed.
            for i in 0..0x1000 {
                assert_eq!(mem.read_obj::<u8>(GuestAddress((1 << 12) + i)).unwrap(), 1);
            }
        }

        // Test the happy case.
        {
            mem.write_obj::<u32>(0x1, GuestAddress(page_addr)).unwrap();
            set_request(&infq, 0, page_addr, SIZE_OF_U32 as u32, VIRTQ_DESC_F_NEXT);

            check_metric_after_block!(
                METRICS.balloon.inflate_count,
                1,
                invoke_handler_for_queue_event(&mut balloon, INFLATE_INDEX)
            );
            check_request_completion(&infq, 0);

            // Check that the page was zeroed.
            for i in 0..0x1000 {
                assert_eq!(mem.read_obj::<u8>(GuestAddress((1 << 12) + i)).unwrap(), 0);
            }
        }
    }

    #[test]
    fn test_deflate() {
        let mut balloon = Balloon::new(0, true, 0, false).unwrap();
        let mem = default_mem();
        let defq = VirtQueue::new(GuestAddress(0), &mem, 16);
        balloon.set_queue(DEFLATE_INDEX, defq.create_queue());
        balloon.activate(mem.clone()).unwrap();

        let page_addr = 0x10;

        // Error case: forgot to trigger deflate event queue.
        {
            set_request(&defq, 0, page_addr, SIZE_OF_U32 as u32, VIRTQ_DESC_F_NEXT);
            check_metric_after_block!(
                METRICS.balloon.event_fails,
                1,
                balloon
                    .process_deflate_queue_event()
                    .unwrap_or_else(report_balloon_event_fail)
            );
            // Verify that nothing got processed.
            assert_eq!(defq.used.idx.get(), 0);
        }

        // Happy case.
        {
            set_request(&defq, 1, page_addr, SIZE_OF_U32 as u32, VIRTQ_DESC_F_NEXT);
            check_metric_after_block!(
                METRICS.balloon.deflate_count,
                1,
                invoke_handler_for_queue_event(&mut balloon, DEFLATE_INDEX)
            );
            check_request_completion(&defq, 1);
        }
    }

    #[test]
    fn test_stats() {
        let mut balloon = Balloon::new(0, true, 1, false).unwrap();
        let mem = default_mem();
        let statsq = VirtQueue::new(GuestAddress(0), &mem, 16);
        balloon.set_queue(STATS_INDEX, statsq.create_queue());
        balloon.activate(mem.clone()).unwrap();

        let page_addr = 0x100;

        // Error case: forgot to trigger stats event queue.
        {
            set_request(&statsq, 0, 0x1000, SIZE_OF_STAT as u32, VIRTQ_DESC_F_NEXT);
            check_metric_after_block!(
                METRICS.balloon.event_fails,
                1,
                balloon
                    .process_stats_queue_event()
                    .unwrap_or_else(report_balloon_event_fail)
            );
            // Verify that nothing got processed.
            assert_eq!(statsq.used.idx.get(), 0);
        }

        // Happy case.
        {
            let swap_out_stat = BalloonStat {
                tag: VIRTIO_BALLOON_S_SWAP_OUT,
                val: 0x1,
            };
            let mem_free_stat = BalloonStat {
                tag: VIRTIO_BALLOON_S_MEMFREE,
                val: 0x5678,
            };

            // Write the stats in memory.
            mem.write_obj::<BalloonStat>(swap_out_stat, GuestAddress(page_addr))
                .unwrap();
            mem.write_obj::<BalloonStat>(
                mem_free_stat,
                GuestAddress(page_addr + SIZE_OF_STAT as u64),
            )
            .unwrap();

            set_request(
                &statsq,
                0,
                page_addr,
                2 * SIZE_OF_STAT as u32,
                VIRTQ_DESC_F_NEXT,
            );
            check_metric_after_block!(METRICS.balloon.stats_updates_count, 1, {
                // Trigger the queue event.
                balloon.queue_events()[STATS_INDEX].write(1).unwrap();
                balloon.process_stats_queue_event().unwrap();
                // Don't check for completion yet.
            });

            let stats = balloon.latest_stats().unwrap();
            let expected_stats = BalloonStats {
                swap_out: Some(0x1),
                free_memory: Some(0x5678),
                ..BalloonStats::default()
            };
            assert_eq!(stats, &expected_stats);

            // Wait for the timer to expire, although as it is non-blocking
            // we could just process the timer event and it would not
            // return an error.
            std::thread::sleep(Duration::from_secs(1));
            check_metric_after_block!(METRICS.balloon.event_fails, 0, {
                // Trigger the timer event, which consumes the stats
                // descriptor index and signals the used queue.
                assert!(balloon.stats_desc_index.is_some());
                assert!(balloon.process_stats_timer_event().is_ok());
                assert!(balloon.stats_desc_index.is_none());
                assert!(balloon.irq_trigger.has_pending_irq(IrqType::Vring));
            });
        }
    }

    #[test]
    fn test_process_balloon_queues() {
        let mut balloon = Balloon::new(0x10, true, 0, false).unwrap();
        let mem = default_mem();
        balloon.activate(mem).unwrap();
        balloon.process_virtio_queues()
    }

    #[test]
    fn test_update_stats_interval() {
        let mut balloon = Balloon::new(0, true, 0, false).unwrap();
        let mem = default_mem();
        balloon.activate(mem).unwrap();
        assert_eq!(
            format!("{:?}", balloon.update_stats_polling_interval(1)),
            "Err(StatisticsStateChange)"
        );
        assert!(balloon.update_stats_polling_interval(0).is_ok());

        let mut balloon = Balloon::new(0, true, 1, false).unwrap();
        let mem = default_mem();
        balloon.activate(mem).unwrap();
        assert_eq!(
            format!("{:?}", balloon.update_stats_polling_interval(0)),
            "Err(StatisticsStateChange)"
        );
        assert!(balloon.update_stats_polling_interval(1).is_ok());
        assert!(balloon.update_stats_polling_interval(2).is_ok());
    }

    #[test]
    fn test_num_pages() {
        let mut balloon = Balloon::new(0, true, 0, false).unwrap();
        // Assert that we can't update an inactive device.
        assert!(balloon.update_size(1).is_err());
        // Switch the state to active.
        balloon.device_state = DeviceState::Activated(
            vm_memory::test_utils::create_guest_memory_unguarded(
                &[(GuestAddress(0x0), 0x1)],
                false,
            )
            .unwrap(),
        );

        assert_eq!(balloon.num_pages(), 0);
        assert_eq!(balloon.actual_pages(), 0);

        // Update fields through the API.
        balloon.update_actual_pages(0x1234);
        balloon.update_num_pages(0x100);
        assert_eq!(balloon.num_pages(), 0x100);
        assert!(balloon.update_size(16).is_ok());

        let mut actual_config = vec![0; CONFIG_SPACE_SIZE];
        balloon.read_config(0, &mut actual_config);
        assert_eq!(actual_config, vec![0x0, 0x10, 0x0, 0x0, 0x34, 0x12, 0, 0]);
        assert_eq!(balloon.num_pages(), 0x1000);
        assert_eq!(balloon.actual_pages(), 0x1234);
        assert_eq!(balloon.size_mb(), 16);

        // Update fields through the config space.
        let expected_config = vec![0x44, 0x33, 0x22, 0x11, 0x78, 0x56, 0x34, 0x12];
        balloon.write_config(0, &expected_config);
        assert_eq!(balloon.num_pages(), 0x1122_3344);
        assert_eq!(balloon.actual_pages(), 0x1234_5678);
    }
}
