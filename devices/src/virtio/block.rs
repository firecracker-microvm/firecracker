// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

use {DeviceEventT, EpollHandler};
use super::{ActivateError, ActivateResult};
use epoll;
use super::{DescriptorChain, Queue, VirtioDevice, INTERRUPT_STATUS_USED_RING, TYPE_BLOCK};
use sys_util::Result as SysResult;
use sys_util::{EventFd, GuestAddress, GuestMemory, GuestMemoryError};
use virtio_sys::virtio_blk::*;

const SECTOR_SHIFT: u8 = 9;
const SECTOR_SIZE: u64 = 0x01 << SECTOR_SHIFT;
const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &'static [u16] = &[QUEUE_SIZE];

pub const QUEUE_AVAIL_EVENT: DeviceEventT = 0;
pub const KILL_EVENT: DeviceEventT = 1;

#[derive(Debug, PartialEq)]
enum RequestType {
    In,
    Out,
    Flush,
    Unsupported(u32),
}

#[derive(Debug)]
enum ParseError {
    /// Guest gave us bad memory addresses
    GuestMemory(GuestMemoryError),
    /// Guest gave us offsets that would have overflowed a usize.
    CheckedOffset(GuestAddress, usize),
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    DescriptorLengthTooSmall,
}

fn request_type(
    mem: &GuestMemory,
    desc_addr: GuestAddress,
) -> result::Result<RequestType, ParseError> {
    let type_ = mem.read_obj_from_addr(desc_addr)
        .map_err(ParseError::GuestMemory)?;
    match type_ {
        VIRTIO_BLK_T_IN => Ok(RequestType::In),
        VIRTIO_BLK_T_OUT => Ok(RequestType::Out),
        VIRTIO_BLK_T_FLUSH => Ok(RequestType::Flush),
        t => Ok(RequestType::Unsupported(t)),
    }
}

fn sector(mem: &GuestMemory, desc_addr: GuestAddress) -> result::Result<u64, ParseError> {
    const SECTOR_OFFSET: usize = 8;
    let addr = match mem.checked_offset(desc_addr, SECTOR_OFFSET) {
        Some(v) => v,
        None => return Err(ParseError::CheckedOffset(desc_addr, SECTOR_OFFSET)),
    };

    mem.read_obj_from_addr(addr)
        .map_err(ParseError::GuestMemory)
}

#[derive(Debug)]
enum ExecuteError {
    Flush(io::Error),
    Read(GuestMemoryError),
    Seek(io::Error),
    Write(GuestMemoryError),
    Unsupported(u32),
}

impl ExecuteError {
    fn status(&self) -> u32 {
        match self {
            &ExecuteError::Flush(_) => VIRTIO_BLK_S_IOERR,
            &ExecuteError::Read(_) => VIRTIO_BLK_S_IOERR,
            &ExecuteError::Seek(_) => VIRTIO_BLK_S_IOERR,
            &ExecuteError::Write(_) => VIRTIO_BLK_S_IOERR,
            &ExecuteError::Unsupported(_) => VIRTIO_BLK_S_UNSUPP,
        }
    }
}

struct Request {
    request_type: RequestType,
    sector: u64,
    data_addr: GuestAddress,
    data_len: u32,
    status_addr: GuestAddress,
}

impl Request {
    fn parse(
        avail_desc: &DescriptorChain,
        mem: &GuestMemory,
    ) -> result::Result<Request, ParseError> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(ParseError::UnexpectedWriteOnlyDescriptor);
        }

        let req_type = request_type(&mem, avail_desc.addr)?;
        let sector = sector(&mem, avail_desc.addr)?;
        let data_desc = avail_desc
            .next_descriptor()
            .ok_or(ParseError::DescriptorChainTooShort)?;
        let status_desc = data_desc
            .next_descriptor()
            .ok_or(ParseError::DescriptorChainTooShort)?;

        if data_desc.is_write_only() && req_type == RequestType::Out {
            return Err(ParseError::UnexpectedWriteOnlyDescriptor);
        }

        if !data_desc.is_write_only() && req_type == RequestType::In {
            return Err(ParseError::UnexpectedReadOnlyDescriptor);
        }

        // The status MUST always be writable
        if !status_desc.is_write_only() {
            return Err(ParseError::UnexpectedReadOnlyDescriptor);
        }

        if status_desc.len < 1 {
            return Err(ParseError::DescriptorLengthTooSmall);
        }

        Ok(Request {
            request_type: req_type,
            sector: sector,
            data_addr: data_desc.addr,
            data_len: data_desc.len,
            status_addr: status_desc.addr,
        })
    }

    fn execute<T: Seek + Read + Write>(
        &self,
        disk: &mut T,
        mem: &GuestMemory,
    ) -> result::Result<u32, ExecuteError> {
        disk.seek(SeekFrom::Start(self.sector << SECTOR_SHIFT))
            .map_err(ExecuteError::Seek)?;
        match self.request_type {
            RequestType::In => {
                mem.read_to_memory(self.data_addr, disk, self.data_len as usize)
                    .map_err(ExecuteError::Read)?;
                return Ok(self.data_len);
            }
            RequestType::Out => {
                mem.write_from_memory(self.data_addr, disk, self.data_len as usize)
                    .map_err(ExecuteError::Write)?;
            }
            RequestType::Flush => disk.flush().map_err(ExecuteError::Flush)?,
            RequestType::Unsupported(t) => return Err(ExecuteError::Unsupported(t)),
        };
        Ok(0)
    }
}

pub struct BlockEpollHandler {
    queues: Vec<Queue>,
    mem: GuestMemory,
    disk_image: File,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    queue_evt: EventFd,
}

impl BlockEpollHandler {
    fn process_queue(&mut self, queue_index: usize) -> bool {
        let queue = &mut self.queues[queue_index];

        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        for avail_desc in queue.iter(&self.mem) {
            let len;
            match Request::parse(&avail_desc, &self.mem) {
                Ok(request) => {
                    let status = match request.execute(&mut self.disk_image, &self.mem) {
                        Ok(l) => {
                            len = l;
                            VIRTIO_BLK_S_OK
                        }
                        Err(e) => {
                            error!("failed executing disk request: {:?}", e);
                            len = 1; // 1 byte for the status
                            e.status()
                        }
                    };
                    // We use unwrap because the request parsing process already checked that the
                    // status_addr was valid.
                    self.mem
                        .write_obj_at_addr(status, request.status_addr)
                        .unwrap();
                }
                Err(e) => {
                    error!("failed processing available descriptor chain: {:?}", e);
                    len = 0;
                }
            }
            used_desc_heads[used_count] = (avail_desc.index, len);
            used_count += 1;
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            queue.add_used(&self.mem, desc_index, len);
        }
        used_count > 0
    }

    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    #[cfg(test)]
    fn set_queue(&mut self, idx: usize, q: Queue) {
        self.queues[idx] = q;
    }
}

impl EpollHandler for BlockEpollHandler {
    fn handle_event(&mut self, device_event: DeviceEventT, _: u32) {
        match device_event {
            QUEUE_AVAIL_EVENT => {
                if let Err(e) = self.queue_evt.read() {
                    error!("failed reading queue EventFd: {:?}", e);
                    return;
                }

                if self.process_queue(0) {
                    self.signal_used_queue();
                }
            }
            KILL_EVENT => {
                //TODO: change this when implementing device removal
                info!("block device killed")
            }
            _ => panic!("unknown token for block device"),
        }
    }
}

pub struct EpollConfig {
    q_avail_token: u64,
    kill_token: u64,
    epoll_raw_fd: RawFd,
    sender: mpsc::Sender<Box<EpollHandler>>,
}

impl EpollConfig {
    pub fn new(
        first_token: u64,
        epoll_raw_fd: RawFd,
        sender: mpsc::Sender<Box<EpollHandler>>,
    ) -> Self {
        EpollConfig {
            q_avail_token: first_token,
            kill_token: first_token + 1,
            epoll_raw_fd,
            sender,
        }
    }
}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block {
    kill_evt: Option<EventFd>,
    disk_image: Option<File>,
    config_space: Vec<u8>,
    epoll_config: EpollConfig,
}

fn build_config_space(disk_size: u64) -> Vec<u8> {
    // We only support disk size, which uses the first two words of the configuration space.
    // If the image is not a multiple of the sector size, the tail bits are not exposed.
    // The config space is little endian.
    let mut config = Vec::with_capacity(8);
    let num_sectors = disk_size >> SECTOR_SHIFT;
    for i in 0..8 {
        config.push((num_sectors >> (8 * i)) as u8);
    }
    config
}

impl Block {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    pub fn new(mut disk_image: File, epoll_config: EpollConfig) -> SysResult<Block> {
        let disk_size = disk_image.seek(SeekFrom::End(0))? as u64;
        if disk_size % SECTOR_SIZE != 0 {
            warn!(
                "Disk size {} is not a multiple of sector size {}; \
                 the remainder will not be visible to the guest.",
                disk_size, SECTOR_SIZE
            );
        }
        Ok(Block {
            kill_evt: None,
            disk_image: Some(disk_image),
            config_space: build_config_space(disk_size),
            epoll_config,
        })
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write(&self.config_space[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt_evt: EventFd,
        status: Arc<AtomicUsize>,
        queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != 1 || queue_evts.len() != 1 {
            error!("virtio-block: expected 1 queue, got {}", queues.len());
            return Err(ActivateError::BadActivate);
        }

        let (self_kill_evt, kill_evt) = match EventFd::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed creating kill EventFd pair: {:?}", e);
                return Err(ActivateError::BadActivate);
            }
        };
        self.kill_evt = Some(self_kill_evt);

        if let Some(disk_image) = self.disk_image.take() {
            let queue_evt = queue_evts.remove(0);

            let queue_evt_raw_fd = queue_evt.as_raw_fd();
            let kill_evt_raw_fd = kill_evt.as_raw_fd();

            let handler = BlockEpollHandler {
                queues,
                mem,
                disk_image,
                interrupt_status: status,
                interrupt_evt,
                queue_evt,
            };

            //the channel should be open at this point
            self.epoll_config.sender.send(Box::new(handler)).unwrap();

            //TODO: barrier needed here by any chance?

            epoll::ctl(
                self.epoll_config.epoll_raw_fd,
                epoll::EPOLL_CTL_ADD,
                queue_evt_raw_fd,
                epoll::Event::new(epoll::EPOLLIN, self.epoll_config.q_avail_token),
            ).map_err(ActivateError::EpollCtl)?;

            epoll::ctl(
                self.epoll_config.epoll_raw_fd,
                epoll::EPOLL_CTL_ADD,
                kill_evt_raw_fd,
                epoll::Event::new(epoll::EPOLLIN, self.epoll_config.kill_token),
            ).map_err(ActivateError::EpollCtl)?;

            return Ok(());
        }

        Err(ActivateError::BadActivate)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::path::PathBuf;
    use std::sync::mpsc::Receiver;

    use libc;
    use sys_util::TempDir;

    use virtio::queue::tests::*;
    use super::*;

    struct DummyBlock {
        block: Block,
        epoll_raw_fd: i32,
        _receiver: Receiver<Box<EpollHandler>>,
    }

    impl DummyBlock {
        fn new() -> Self {
            let epoll_raw_fd = epoll::create(true).unwrap();
            let (sender, _receiver) = mpsc::channel();

            let epoll_config = EpollConfig::new(0, epoll_raw_fd, sender);

            let tempdir = TempDir::new("/tmp/block_test").unwrap();
            let mut path = PathBuf::from(tempdir.as_path().unwrap());
            path.push("disk_image");
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&path)
                .unwrap();
            f.set_len(0x1000).unwrap();

            DummyBlock {
                block: Block::new(f, epoll_config).unwrap(),
                epoll_raw_fd,
                _receiver,
            }
        }

        fn block(&mut self) -> &mut Block {
            &mut self.block
        }
    }

    impl Drop for DummyBlock {
        fn drop(&mut self) {
            unsafe { libc::close(self.epoll_raw_fd) };
        }
    }

    #[test]
    fn test_request_type() {
        let m = &GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
        let a = GuestAddress(0);

        // We write values associated with different request type at an address in memory,
        // and verify the request type is parsed correctly.

        m.write_obj_at_addr::<u32>(VIRTIO_BLK_T_IN, a).unwrap();
        assert_eq!(request_type(m, a).unwrap(), RequestType::In);

        m.write_obj_at_addr::<u32>(VIRTIO_BLK_T_OUT, a).unwrap();
        assert_eq!(request_type(m, a).unwrap(), RequestType::Out);

        m.write_obj_at_addr::<u32>(VIRTIO_BLK_T_FLUSH, a).unwrap();
        assert_eq!(request_type(m, a).unwrap(), RequestType::Flush);

        // The value written here should be invalid.
        m.write_obj_at_addr::<u32>(VIRTIO_BLK_T_FLUSH + 10, a)
            .unwrap();
        assert_eq!(
            request_type(m, a).unwrap(),
            RequestType::Unsupported(VIRTIO_BLK_T_FLUSH + 10)
        );

        // The provided address cannot be read, as it's outside the memory space.
        let a = GuestAddress(0x1000);
        assert!(request_type(m, a).is_err())
    }

    #[test]
    fn test_sector() {
        let m = &GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
        let a = GuestAddress(0);

        // Here we test that a sector number is parsed correctly from memory. The actual sector
        // number is expected to be found 8 bytes after the address provided as parameter to the
        // sector() function.

        m.write_obj_at_addr::<u64>(123454321, a.checked_add(8).unwrap())
            .unwrap();
        assert_eq!(sector(m, a).unwrap(), 123454321);

        // Reading from a slightly different address should not lead a correct result in this case.
        assert_ne!(sector(m, a.checked_add(1).unwrap()).unwrap(), 123454321);

        // The provided address is outside the valid memory range.
        assert!(sector(m, a.checked_add(0x1000).unwrap()).is_err());
    }

    #[test]
    fn test_parse() {
        let m = &GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), &m, 16);

        assert!(vq.end().0 < 0x1000);

        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);

        {
            let mut q = vq.create_queue();
            // write only request type descriptor
            vq.dtable[0].set(0x1000, 0x1000, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj_at_addr::<u32>(VIRTIO_BLK_T_OUT, GuestAddress(0x1000))
                .unwrap();
            m.write_obj_at_addr::<u64>(114, GuestAddress(0x1000 + 8))
                .unwrap();
            assert!(match Request::parse(&q.iter(m).next().unwrap(), m) {
                Err(ParseError::UnexpectedWriteOnlyDescriptor) => true,
                _ => false,
            });
        }

        {
            let mut q = vq.create_queue();
            // chain too short; no data_desc
            vq.dtable[0].flags.set(0);
            assert!(match Request::parse(&q.iter(m).next().unwrap(), m) {
                Err(ParseError::DescriptorChainTooShort) => true,
                _ => false,
            });
        }

        {
            let mut q = vq.create_queue();
            // chain too short; no status desc
            vq.dtable[0].flags.set(VIRTQ_DESC_F_NEXT);
            vq.dtable[1].set(0x2000, 0x1000, 0, 2);
            assert!(match Request::parse(&q.iter(m).next().unwrap(), m) {
                Err(ParseError::DescriptorChainTooShort) => true,
                _ => false,
            });
        }

        {
            let mut q = vq.create_queue();
            // write only data for OUT
            vq.dtable[1]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            vq.dtable[2].set(0x3000, 0, 0, 0);
            assert!(match Request::parse(&q.iter(m).next().unwrap(), m) {
                Err(ParseError::UnexpectedWriteOnlyDescriptor) => true,
                _ => false,
            });
        }

        {
            let mut q = vq.create_queue();
            // read only data for IN
            m.write_obj_at_addr::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
                .unwrap();
            vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
            assert!(match Request::parse(&q.iter(m).next().unwrap(), m) {
                Err(ParseError::UnexpectedReadOnlyDescriptor) => true,
                _ => false,
            });
        }

        {
            let mut q = vq.create_queue();
            // status desc not writable
            vq.dtable[1]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            assert!(match Request::parse(&q.iter(m).next().unwrap(), m) {
                Err(ParseError::UnexpectedReadOnlyDescriptor) => true,
                _ => false,
            });
        }

        {
            let mut q = vq.create_queue();
            // status desc too small
            vq.dtable[2].flags.set(VIRTQ_DESC_F_WRITE);
            assert!(match Request::parse(&q.iter(m).next().unwrap(), m) {
                Err(ParseError::DescriptorLengthTooSmall) => true,
                _ => false,
            });
        }

        {
            let mut q = vq.create_queue();
            // should be OK now
            vq.dtable[2].len.set(0x1000);
            let r = Request::parse(&q.iter(m).next().unwrap(), m).unwrap();

            assert_eq!(r.request_type, RequestType::In);
            assert_eq!(r.sector, 114);
            assert_eq!(r.data_addr, GuestAddress(0x2000));
            assert_eq!(r.data_len, 0x1000);
            assert_eq!(r.status_addr, GuestAddress(0x3000));
        }
    }

    #[test]
    fn test_virtio_device() {
        let mut dummy = DummyBlock::new();
        let b = dummy.block();

        assert_eq!(b.device_type(), TYPE_BLOCK);

        {
            let x = b.queue_max_sizes();
            assert_eq!(x, QUEUE_SIZES);

            // power of 2?
            for &y in x {
                assert!(y > 0 && y & (y - 1) == 0);
            }
        }

        let mut num_sectors = [0u8; 4];
        b.read_config(0, &mut num_sectors);
        // size is 0x1000, so num_sectors is 8 (4096/512).
        assert_eq!([0x08, 0x00, 0x00, 0x00], num_sectors);
        let mut msw_sectors = [0u8; 4];
        b.read_config(4, &mut msw_sectors);
        // size is 0x1000, so msw_sectors is 0.
        assert_eq!([0x00, 0x00, 0x00, 0x00], msw_sectors);

        // test activate
        let m = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
        let ievt = EventFd::new().unwrap();
        let stat = Arc::new(AtomicUsize::new(0));

        let vq = VirtQueue::new(GuestAddress(0), &m, 16);
        let queues = vec![vq.create_queue()];
        let queue_evts = vec![EventFd::new().unwrap()];

        let result = b.activate(m.clone(), ievt, stat, queues, queue_evts);

        assert!(result.is_ok());
    }

    fn invoke_handler(h: &mut BlockEpollHandler, e: DeviceEventT) {
        h.interrupt_evt.write(1).unwrap();
        h.queue_evt.write(1).unwrap();
        h.handle_event(e, 0);
        assert_eq!(h.interrupt_evt.read(), Ok(2));
    }

    #[test]
    fn test_handler() {
        let mut dummy = DummyBlock::new();
        let b = dummy.block();
        let m = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), &m, 16);

        assert!(vq.end().0 < 0x1000);

        let queues = vec![vq.create_queue()];
        let mem = m.clone();
        let disk_image = b.disk_image.take().unwrap();
        let status = Arc::new(AtomicUsize::new(0));
        let interrupt_evt = EventFd::new().unwrap();
        let queue_evt = EventFd::new().unwrap();

        let mut h = BlockEpollHandler {
            queues,
            mem,
            disk_image,
            interrupt_status: status,
            interrupt_evt,
            queue_evt,
        };

        for i in 0..3 {
            vq.avail.ring[i].set(i as u16);
            vq.dtable[i].set(
                (0x1000 * (i + 1)) as u64,
                0x1000,
                VIRTQ_DESC_F_NEXT,
                (i + 1) as u16,
            );
        }

        vq.dtable[1]
            .flags
            .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
        vq.dtable[2].flags.set(VIRTQ_DESC_F_WRITE);
        vq.avail.idx.set(1);

        // dtable[1] is the data descriptor
        let data_addr = GuestAddress(vq.dtable[1].addr.get() as usize);
        // dtable[2] is the status descriptor
        let status_addr = GuestAddress(vq.dtable[2].addr.get() as usize);

        {
            // let's start with a request that does not parse
            // request won't be valid bc the first desc is write-only
            vq.dtable[0]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            m.write_obj_at_addr::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
                .unwrap();

            invoke_handler(&mut h, QUEUE_AVAIL_EVENT);

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);
        }

        // now we generate some request execute failures

        {
            // reset the queue to reuse descriptors & memory
            vq.used.idx.set(0);
            h.set_queue(0, vq.create_queue());

            // first desc no longer writable
            vq.dtable[0].flags.set(VIRTQ_DESC_F_NEXT);
            // let's generate a seek execute error caused by a very large sector number
            m.write_obj_at_addr::<u64>(0xfffffffff, GuestAddress(0x1000 + 8))
                .unwrap();

            invoke_handler(&mut h, QUEUE_AVAIL_EVENT);

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(
                m.read_obj_from_addr::<u8>(status_addr).unwrap(),
                VIRTIO_BLK_S_IOERR
            );
        }

        {
            vq.used.idx.set(0);
            h.set_queue(0, vq.create_queue());

            // set sector to a valid number but large enough that the full 0x1000 read will fail
            m.write_obj_at_addr::<u64>(10, GuestAddress(0x1000 + 8))
                .unwrap();

            invoke_handler(&mut h, QUEUE_AVAIL_EVENT);

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(
                m.read_obj_from_addr::<u8>(status_addr).unwrap(),
                VIRTIO_BLK_S_IOERR
            );
        }

        {
            vq.used.idx.set(0);
            h.set_queue(0, vq.create_queue());

            // set sector to 0
            m.write_obj_at_addr::<u64>(0, GuestAddress(0x1000 + 8))
                .unwrap();
            // ... but generate an unsupported request
            m.write_obj_at_addr::<u32>(8, GuestAddress(0x1000)).unwrap();

            invoke_handler(&mut h, QUEUE_AVAIL_EVENT);

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(
                m.read_obj_from_addr::<u8>(status_addr).unwrap(),
                VIRTIO_BLK_S_UNSUPP
            );
        }

        // now let's write something and read it back

        {
            // write

            vq.used.idx.set(0);
            h.set_queue(0, vq.create_queue());

            m.write_obj_at_addr::<u32>(VIRTIO_BLK_T_OUT, GuestAddress(0x1000))
                .unwrap();
            // make data read only, 8 bytes in len, and set the actual value to be written
            vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
            vq.dtable[1].len.set(8);
            m.write_obj_at_addr::<u64>(123456789, data_addr).unwrap();

            invoke_handler(&mut h, QUEUE_AVAIL_EVENT);
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);
            assert_eq!(
                m.read_obj_from_addr::<u8>(status_addr).unwrap(),
                VIRTIO_BLK_S_OK
            );
        }

        {
            // read

            vq.used.idx.set(0);
            h.set_queue(0, vq.create_queue());

            m.write_obj_at_addr::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
                .unwrap();
            vq.dtable[1]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);

            invoke_handler(&mut h, QUEUE_AVAIL_EVENT);
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, vq.dtable[1].len.get());
            assert_eq!(
                m.read_obj_from_addr::<u8>(status_addr).unwrap(),
                VIRTIO_BLK_S_OK
            );
            assert_eq!(m.read_obj_from_addr::<u64>(data_addr).unwrap(), 123456789);
        }

        {
            // finally, let's also do a flush request

            vq.used.idx.set(0);
            h.set_queue(0, vq.create_queue());

            m.write_obj_at_addr::<u32>(VIRTIO_BLK_T_FLUSH, GuestAddress(0x1000))
                .unwrap();

            invoke_handler(&mut h, QUEUE_AVAIL_EVENT);
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);
            assert_eq!(
                m.read_obj_from_addr::<u8>(status_addr).unwrap(),
                VIRTIO_BLK_S_OK
            );
        }

        // can be called like this for now, because it currently doesn't really do anything
        // besides outputting some message
        h.handle_event(KILL_EVENT, 0);
    }
}
