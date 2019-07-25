// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use std;
use std::cmp;
use std::fmt::{self, Display};
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use msg_socket::MsgReceiver;
use sys_util::{
    self, error, info, warn, EventFd, GuestAddress, GuestMemory, PollContext, PollToken,
};
use vm_control::{BalloonControlCommand, BalloonControlResponseSocket};
use super::{
    DescriptorChain, Queue, VirtioDevice, INTERRUPT_STATUS_CONFIG_CHANGED,
    INTERRUPT_STATUS_USED_RING, TYPE_BALLOON, VIRTIO_F_VERSION_1,
};
#[derive(Debug)]
pub enum BalloonError {
    /// Request to adjust memory size can't provide the number of pages requested.
    NotEnoughPages,
    /// Failure wriitng the config notification event.
    WritingConfigEvent(sys_util::Error),
}
pub type Result<T> = std::result::Result<T, BalloonError>;
impl Display for BalloonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::BalloonError::*;
        match self {
            NotEnoughPages => write!(f, "not enough pages"),
            WritingConfigEvent(e) => write!(f, "failed to write config event: {}", e),
        }
    }
}
// Balloon has three virt IO queues: Inflate, Deflate, and Stats.
// Stats is currently not used.
const QUEUE_SIZE: u16 = 128;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE];
const VIRTIO_BALLOON_PFN_SHIFT: u32 = 12;
// The feature bitmap for virtio balloon
const VIRTIO_BALLOON_F_MUST_TELL_HOST: u32 = 0; // Tell before reclaiming pages
const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 2; // Deflate balloon on OOM
// BalloonConfig is modified by the worker and read from the device thread.
#[derive(Default)]
struct BalloonConfig {
    num_pages: AtomicUsize,
    actual_pages: AtomicUsize,
}
struct Worker {
    mem: GuestMemory,
    inflate_queue: Queue,
    deflate_queue: Queue,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    interrupt_resample_evt: EventFd,
    config: Arc<BalloonConfig>,
    command_socket: BalloonControlResponseSocket,
}
fn valid_inflate_desc(desc: &DescriptorChain) -> bool {
    !desc.is_write_only() && desc.len % 4 == 0
}
impl Worker {
    fn process_inflate_deflate(&mut self, inflate: bool) -> bool {
        let queue = if inflate {
            &mut self.inflate_queue
        } else {
            &mut self.deflate_queue
        };
        let mut needs_interrupt = false;
        while let Some(avail_desc) = queue.pop(&self.mem) {
            if inflate && valid_inflate_desc(&avail_desc) {
                let num_addrs = avail_desc.len / 4;
                for i in 0..num_addrs as usize {
                    let addr = match avail_desc.addr.checked_add((i * 4) as u64) {
                        Some(a) => a,
                        None => break,
                    };
                    let guest_input: u32 = match self.mem.read_obj_from_addr(addr) {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    let guest_address =
                        GuestAddress((guest_input as u64) << VIRTIO_BALLOON_PFN_SHIFT);
                    if self
                        .mem
                        .remove_range(guest_address, 1 << VIRTIO_BALLOON_PFN_SHIFT)
                        .is_err()
                    {
                        warn!("Marking pages unused failed; addr={}", guest_address);
                        continue;
                    }
                }
            }
            queue.add_used(&self.mem, avail_desc.index, 0);
            needs_interrupt = true;
        }
        needs_interrupt
    }
    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }
    fn signal_config_changed(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_CONFIG_CHANGED as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }
    fn run(&mut self, mut queue_evts: Vec<EventFd>, kill_evt: EventFd) {
        #[derive(PartialEq, PollToken)]
        enum Token {
            Inflate,
            Deflate,
            CommandSocket,
            InterruptResample,
            Kill,
        }
        let inflate_queue_evt = queue_evts.remove(0);
        let deflate_queue_evt = queue_evts.remove(0);
        let poll_ctx: PollContext<Token> = match PollContext::build_with(&[
            (&inflate_queue_evt, Token::Inflate),
            (&deflate_queue_evt, Token::Deflate),
            (&self.command_socket, Token::CommandSocket),
            (&self.interrupt_resample_evt, Token::InterruptResample),
            (&kill_evt, Token::Kill),
        ]) {
            Ok(pc) => pc,
            Err(e) => {
                error!("failed creating PollContext: {}", e);
                return;
            }
        };
        'poll: loop {
            let events = match poll_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed polling for events: {}", e);
                    break;
                }
            };
            let mut needs_interrupt = false;
            for event in events.iter_readable() {
                match event.token() {
                    Token::Inflate => {
                        if let Err(e) = inflate_queue_evt.read() {
                            error!("failed reading inflate queue EventFd: {}", e);
                            break 'poll;
                        }
                        needs_interrupt |= self.process_inflate_deflate(true);
                    }
                    Token::Deflate => {
                        if let Err(e) = deflate_queue_evt.read() {
                            error!("failed reading deflate queue EventFd: {}", e);
                            break 'poll;
                        }
                        needs_interrupt |= self.process_inflate_deflate(false);
                    }
                    Token::CommandSocket => {
                        if let Ok(req) = self.command_socket.recv() {
                            match req {
                                BalloonControlCommand::Adjust { num_bytes } => {
                                    let num_pages =
                                        (num_bytes >> VIRTIO_BALLOON_PFN_SHIFT) as usize;
                                    info!("ballon config changed to consume {} pages", num_pages);
                                    self.config.num_pages.store(num_pages, Ordering::Relaxed);
                                    self.signal_config_changed();
                                }
                            };
                        }
                    }
                    Token::InterruptResample => {
                        let _ = self.interrupt_resample_evt.read();
                        if self.interrupt_status.load(Ordering::SeqCst) != 0 {
                            self.interrupt_evt.write(1).unwrap();
                        }
                    }
                    Token::Kill => break 'poll,
                }
            }
            for event in events.iter_hungup() {
                if event.token() == Token::CommandSocket && !event.readable() {
                    // If this call fails, the command socket was already removed from the
                    // PollContext.
                    let _ = poll_ctx.delete(&self.command_socket);
                }
            }
            if needs_interrupt {
                self.signal_used_queue();
            }
        }
    }
}
/// Virtio device for memory balloon inflation/deflation.
pub struct Balloon {
    command_socket: Option<BalloonControlResponseSocket>,
    config: Arc<BalloonConfig>,
    features: u64,
    kill_evt: Option<EventFd>,
}
impl Balloon {
    /// Create a new virtio balloon device.
    pub fn new(command_socket: BalloonControlResponseSocket) -> Result<Balloon> {
        Ok(Balloon {
            command_socket: Some(command_socket),
            config: Arc::new(BalloonConfig {
                num_pages: AtomicUsize::new(0),
                actual_pages: AtomicUsize::new(0),
            }),
            kill_evt: None,
            // TODO(dgreid) - Add stats queue feature.
            features: 1 << VIRTIO_BALLOON_F_MUST_TELL_HOST | 1 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM,
        })
    }
}
impl Drop for Balloon {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do with a failure.
            let _ = kill_evt.write(1);
        }
    }
}
impl VirtioDevice for Balloon {
    fn keep_fds(&self) -> Vec<RawFd> {
        vec![self.command_socket.as_ref().unwrap().as_raw_fd()]
    }
    fn device_type(&self) -> u32 {
        TYPE_BALLOON
    }
    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }
    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        if offset >= 8 {
            return;
        }
        let num_pages = self.config.num_pages.load(Ordering::Relaxed) as u32;
        let actual_pages = self.config.actual_pages.load(Ordering::Relaxed) as u32;
        let mut config = [0u8; 8];
        // These writes can't fail as they fit in the declared array so unwrap is fine.
        (&mut config[0..])
            .write_u32::<LittleEndian>(num_pages)
            .unwrap();
        (&mut config[4..])
            .write_u32::<LittleEndian>(actual_pages)
            .unwrap();
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against the length of config.
            data.write_all(&config[offset as usize..cmp::min(end, 8) as usize])
                .unwrap();
        }
    }
    fn write_config(&mut self, offset: u64, mut data: &[u8]) {
        // Only allow writing to `actual` pages from the guest.
        if offset != 4 || data.len() != 4 {
            return;
        }
        // This read can't fail as it fits in the declared array so unwrap is fine.
        let new_actual: u32 = data.read_u32::<LittleEndian>().unwrap();
        self.config
            .actual_pages
            .store(new_actual as usize, Ordering::Relaxed);
    }
    fn features(&self) -> u64 {
        1 << VIRTIO_BALLOON_F_MUST_TELL_HOST
            | 1 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM
            | 1 << VIRTIO_F_VERSION_1
    }
    fn ack_features(&mut self, value: u64) {
        self.features &= value;
    }
    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt_evt: EventFd,
        interrupt_resample_evt: EventFd,
        status: Arc<AtomicUsize>,
        mut queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) {
        if queues.len() != QUEUE_SIZES.len() || queue_evts.len() != QUEUE_SIZES.len() {
            return;
        }
        let (self_kill_evt, kill_evt) = match EventFd::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed to create kill EventFd pair: {}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);
        let config = self.config.clone();
        let command_socket = self.command_socket.take().unwrap();
        let worker_result = thread::Builder::new()
            .name("virtio_balloon".to_string())
            .spawn(move || {
                let mut worker = Worker {
                    mem,
                    inflate_queue: queues.remove(0),
                    deflate_queue: queues.remove(0),
                    interrupt_status: status,
                    interrupt_evt,
                    interrupt_resample_evt,
                    command_socket,
                    config,
                };
                worker.run(queue_evts, kill_evt);
            });
        if let Err(e) = worker_result {
            error!("failed to spawn virtio_balloon worker: {}", e);
            return;
        }
    }
}
