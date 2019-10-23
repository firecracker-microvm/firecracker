// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::mem;
use std::result;

use libc::stat as FileStat;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;

use std::ffi::{CStr, CString};
use sys_util::fs::{
    close, fchmod, fchown, fstatat, fstatvfs, mkdirat, mknodat, open, openat, readlinkat,
    symlinkat, unlinkat, with_cred,
};

use sys_util::fs::Dir;

use libc::statvfs as Statvfs;

use super::util::FuseDirent;
use fuse_gen::fuse::*;

use libc::{dev_t, gid_t, mode_t, uid_t};

use memory_model::{GuestAddress, GuestMemory};

use super::super::DescriptorChain;

use super::error::ExecuteError;

/// The max size of write requests from the kernel. The absolute minimum is 4k,
/// FUSE recommends at least 128k, max 16M. The FUSE default is 128k.
const FUSE_MAX_WRITE_SIZE: usize = 16 * 1024 * 1024;

const FUSE_KERNEL_VERSION: u32 = 7;
const FUSE_KERNEL_MINOR_VERSION: u32 = 19;
const FUSE_INIT_FLAGS: u32 = FUSE_ASYNC_READ | FUSE_NO_OPENDIR_SUPPORT;
const FUSE_DEFAULT_MAX_BACKGROUND: u16 = 12;
const FUSE_DEFAULT_CONGESTION_THRESHOLD: u16 = (FUSE_DEFAULT_MAX_BACKGROUND * 3 / 4);

#[derive(Debug)]
pub enum VtfsError {
    /// Guest gave us bad memory addresses.
    // GuestMemory(GuestMemoryError),
    /// Guest gave us offsets that would have overflowed a usize.
    // CheckedOffset(GuestAddress, usize),
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// Guest gave us a read only descriptor that protocol says to write to.
    // UnexpectedReadOnlyDescriptor,
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    // DescriptorLengthTooSmall,
    /// Getting a block's metadata fails for any reason.
    // GetFileMetadata,
    /// The requested operation would cause a seek beyond disk end.
    InvalidOffset,
    // Not Found Inode
    // NotFoundInodeError,
}

#[derive(Clone, Copy)]
pub struct Request<'a> {
    memory: &'a GuestMemory,
    in_header: fuse_in_header,
    in_arg_addr: GuestAddress,
    in_arg_len: u32,
    out_header_addr: GuestAddress,
    out_arg_addr: GuestAddress,
}

impl<'a> Request<'a> {
    pub fn parse<'k>(
        avail_desc: &DescriptorChain,
        mem: &'k GuestMemory,
    ) -> result::Result<Request<'k>, VtfsError> {
        if avail_desc.is_write_only() {
            return Err(VtfsError::UnexpectedWriteOnlyDescriptor);
        }

        let mut r = Request {
            memory: mem,
            in_header: mem
                .read_obj_from_addr(avail_desc.addr)
                .map_err(|_| VtfsError::InvalidOffset)?,
            in_arg_addr: GuestAddress(0),
            in_arg_len: 0,
            out_header_addr: GuestAddress(0),
            out_arg_addr: GuestAddress(0),
        };
        r.check_chain(avail_desc).map(|_| r)
    }

    #[allow(non_upper_case_globals)]
    pub fn execute(&self, fs: &mut FuseBackend) -> result::Result<u32, ExecuteError> {
        match self.in_header.opcode {
            fuse_opcode_FUSE_INIT => fs.do_init(self),
            fuse_opcode_FUSE_GETATTR => fs.do_getattr(self),
            fuse_opcode_FUSE_LOOKUP => fs.do_lookup(self),
            fuse_opcode_FUSE_OPENDIR => fs.do_opendir(self),
            fuse_opcode_FUSE_READDIR => fs.do_readdir(self),
            fuse_opcode_FUSE_ACCESS => fs.do_access(self),
            fuse_opcode_FUSE_FORGET => fs.do_forget(self),
            fuse_opcode_FUSE_RELEASEDIR => fs.do_releasedir(self),
            fuse_opcode_FUSE_STATFS => fs.do_statfs(self),
            fuse_opcode_FUSE_MKNOD => fs.do_mknod(self),
            fuse_opcode_FUSE_MKDIR => fs.do_mkdir(self),
            fuse_opcode_FUSE_RMDIR => fs.do_rmdir(self),
            fuse_opcode_FUSE_SETATTR => fs.do_setattr(self),
            fuse_opcode_FUSE_UNLINK => fs.do_unlink(self),
            fuse_opcode_FUSE_SYMLINK => fs.do_symlink(self),
            fuse_opcode_FUSE_READLINK => fs.do_readlink(self),
            _ => Err(ExecuteError::InvalidMethod),
        }
    }

    #[allow(non_upper_case_globals)]
    fn check_chain(&mut self, avail_desc: &DescriptorChain) -> result::Result<(), VtfsError> {
        match self.in_header.opcode {
            // only in_header
            fuse_opcode_FUSE_FORGET => {
                self.in_arg_addr = avail_desc
                    .addr
                    .unchecked_add(mem::size_of::<fuse_in_header>());
            }
            // in_header + in_arg + out_header
            fuse_opcode_FUSE_RELEASEDIR
            | fuse_opcode_FUSE_ACCESS
            | fuse_opcode_FUSE_RMDIR
            | fuse_opcode_FUSE_UNLINK => {
                let in_arg_desc = avail_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;
                self.in_arg_addr = in_arg_desc.addr;
                self.in_arg_len = in_arg_desc.len;

                let out_header_desc = in_arg_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;
                self.out_header_addr = out_header_desc.addr;
            }
            // in_header + out_header + out_arg
            fuse_opcode_FUSE_STATFS | fuse_opcode_FUSE_READLINK => {
                let out_header_desc = avail_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;
                self.out_header_addr = out_header_desc.addr;

                let out_arg_desc = out_header_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;
                self.out_arg_addr = out_arg_desc.addr;
            }

            // in_header + in_arg + out_header + out_arg
            _ => {
                let in_arg_desc = avail_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;
                let out_header_desc = in_arg_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;

                let out_arg_desc = out_header_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;

                self.in_arg_addr = in_arg_desc.addr;
                self.in_arg_len = in_arg_desc.len;
                self.out_header_addr = out_header_desc.addr;
                self.out_arg_addr = out_arg_desc.addr;
            }
        }

        Ok(())
    }

    fn send_arg<T: memory_model::DataInit>(&self, arg: T) -> u32 {
        let our_header = fuse_out_header {
            len: (mem::size_of::<fuse_out_header>() + mem::size_of::<T>()) as u32,
            error: 0,
            unique: self.in_header.unique,
        };

        // We use unwrap because the request parsing process already checked that the
        // addr was valid.
        self.memory
            .write_obj_at_addr(our_header, self.out_header_addr)
            .unwrap();
        self.memory
            .write_obj_at_addr(arg, self.out_arg_addr)
            .unwrap();

        our_header.len
    }

    fn send_slice(&self, buf: &[u8]) -> u32 {
        let our_header = fuse_out_header {
            len: (mem::size_of::<fuse_out_header>() + buf.len()) as u32,
            error: 0,
            unique: self.in_header.unique,
        };

        // We use unwrap because the request parsing process already checked that the
        // addr was valid.
        self.memory
            .write_obj_at_addr(our_header, self.out_header_addr)
            .unwrap();
        self.memory
            .write_slice_at_addr(buf, self.out_arg_addr)
            .unwrap();

        our_header.len
    }

    fn send_dirent_vec(&self, arg: Vec<FuseDirent>) -> u32 {
        let mut arg_len = 0;
        for entry in arg.iter() {
            arg_len += entry.aligned_size();
        }

        let our_header = fuse_out_header {
            len: (mem::size_of::<fuse_out_header>() + arg_len) as u32,
            error: 0,
            unique: self.in_header.unique,
        };

        // We use unwrap because the request parsing process already checked that the
        // addr was valid.
        self.memory
            .write_obj_at_addr(our_header, self.out_header_addr)
            .unwrap();
        let mut dirent_addr = self.out_arg_addr;
        for element in arg.iter() {
            element.write_to_memory(self.memory, dirent_addr);
            dirent_addr = dirent_addr.unchecked_add(element.aligned_size());
        }

        our_header.len
    }

    pub fn send_err(&self, err: i32) -> u32 {
        let our_header = fuse_out_header {
            len: (mem::size_of::<fuse_out_header>()) as u32,
            error: -err,
            unique: self.in_header.unique,
        };

        // We use unwrap because the request parsing process already checked that the
        // addr was valid.
        self.memory
            .write_obj_at_addr(our_header, self.out_header_addr)
            .unwrap();

        our_header.len
    }
}

#[derive(Debug)]
struct InodeHandler {
    fd: RawFd,
    host_inode: HostInode,
}

impl InodeHandler {
    fn new(path: &str) -> Option<InodeHandler> {
        let oflag = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_RDONLY;
        let name = CString::new(path).ok()?;
        let fd = open(&name, oflag).ok()?;
        let at_flag = libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW;
        let filestat = fstatat(fd, None, at_flag).ok()?;

        Some(InodeHandler {
            fd: fd,
            host_inode: HostInode {
                st_dev: filestat.st_dev,
                st_ino: filestat.st_ino,
            },
        })
    }

    fn lookup(&self, path: &CStr) -> result::Result<InodeHandler, ExecuteError> {
        let oflag = libc::O_PATH | libc::O_NOFOLLOW;
        let new_fd = openat(self.fd, Some(path), oflag)?;

        let at_flag = libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW;
        let filestat = fstatat(new_fd, None, at_flag)?;

        Ok(InodeHandler {
            fd: new_fd,
            host_inode: HostInode {
                st_dev: filestat.st_dev,
                st_ino: filestat.st_ino,
            },
        })
    }

    fn metadata(&self) -> result::Result<FileStat, ExecuteError> {
        let at_flag = libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW;
        fstatat(self.fd, None, at_flag).map_err(|e| ExecuteError::from(e))
    }

    fn opendir(&self) -> result::Result<Dir, ExecuteError> {
        let oflg = libc::O_RDONLY;
        Dir::openat(self.fd, None, oflg).map_err(|e| ExecuteError::from(e))
    }

    fn fstatvfs(&self) -> result::Result<Statvfs, ExecuteError> {
        fstatvfs(self.as_raw_fd()).map_err(|e| ExecuteError::from(e))
    }

    fn mknod(&self, name: &CStr, mode: mode_t, dev: dev_t) -> result::Result<(), ExecuteError> {
        mknodat(self.fd, name, mode, dev).map_err(|e| ExecuteError::from(e))
    }
}

impl AsRawFd for InodeHandler {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for InodeHandler {
    fn drop(&mut self) {
        close(self.fd).unwrap_or_else(|e| {
            error!("close file handler {} failed with error {}", self.fd, e);
        });
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
struct HostInode {
    st_dev: u64,
    st_ino: u64,
}

#[derive(Default)]
struct InodeMap {
    ino_map: HashMap<u64, InodeHandler>,
    attr_map: HashMap<HostInode, u64>,
    next_key: u64,
}

impl InodeMap {
    fn new(start_key: u64) -> InodeMap {
        InodeMap {
            next_key: start_key,
            ino_map: HashMap::default(),
            attr_map: HashMap::default(),
        }
    }
    fn add(&mut self, v: InodeHandler) -> u64 {
        let ino = self.next_key;
        self.next_key += 1;

        // let id = v.id();
        let host_inode = v.host_inode;
        self.ino_map.insert(ino, v);
        self.attr_map.insert(host_inode, ino);
        ino
    }

    fn remove(&mut self, ino: u64) {
        if let Some(aaaa) = self.ino_map.get(&ino) {
            self.attr_map.remove(&aaaa.host_inode);
        }
        self.ino_map.remove(&ino);
    }

    // TO DO: not necessary ?
    fn identify(&mut self, inode: InodeHandler) -> u64 {
        match self.attr_map.get(&inode.host_inode) {
            Some(ino) => *ino,
            None => self.add(inode),
        }
    }

    fn get(&self, ino: u64) -> result::Result<&InodeHandler, ExecuteError> {
        self.ino_map.get(&ino).ok_or(ExecuteError::UnknownHandle)
    }
}

struct FDMap<V> {
    map: HashMap<u64, V>,
    next_key: u64,
}

impl<V> FDMap<V> {
    fn new(start_key: u64) -> FDMap<V> {
        FDMap {
            map: HashMap::default(),
            next_key: start_key,
        }
    }

    fn insert(&mut self, value: V) -> u64 {
        let key = self.next_key;
        self.next_key += 1;

        self.map.insert(key, value);
        key
    }

    fn remove(&mut self, key: u64) {
        self.map.remove(&key);
    }

    // fn get(&self, key: u64) -> Option<&V> {
    //     self.map.get(&key)
    // }

    fn get_mut(&mut self, key: u64) -> result::Result<&mut V, ExecuteError> {
        self.map.get_mut(&key).ok_or(ExecuteError::UnknownHandle)
    }
}

pub struct FuseBackend {
    dir_map: FDMap<Dir>,
    ino_map: InodeMap,
}

impl FuseBackend {
    pub fn new(fs_path: &str) -> Option<FuseBackend> {
        let mut ino_map = InodeMap::new(1);
        let root_inode = InodeHandler::new(fs_path)?;
        ino_map.add(root_inode);

        Some(FuseBackend {
            dir_map: FDMap::new(1),
            ino_map: ino_map,
        })
    }

    pub fn do_init(&self, request: &Request) -> result::Result<u32, ExecuteError> {
        let guest_mem = request.memory;
        let in_arg: fuse_init_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let mut out_arg = fuse_init_out::default();
        out_arg.major = FUSE_KERNEL_VERSION;
        out_arg.minor = FUSE_KERNEL_MINOR_VERSION;
        out_arg.max_readahead = in_arg.max_readahead;
        out_arg.flags = in_arg.flags & FUSE_INIT_FLAGS;
        out_arg.max_background = FUSE_DEFAULT_MAX_BACKGROUND;
        out_arg.congestion_threshold = FUSE_DEFAULT_CONGESTION_THRESHOLD;
        out_arg.max_write = FUSE_MAX_WRITE_SIZE as u32;

        Ok(request.send_arg(out_arg))
    }

    pub fn do_getattr(&self, request: &Request) -> result::Result<u32, ExecuteError> {
        // not use fuse_getattr_in
        let ino = request.in_header.nodeid;

        let inode = self.ino_map.get(ino)?;
        let filestat = inode.metadata()?;
        let attr = fuse_attr {
            ino: filestat.st_ino,
            size: filestat.st_size as u64,
            blocks: filestat.st_size as u64,
            atime: filestat.st_atime as u64,
            mtime: filestat.st_mtime as u64,
            ctime: filestat.st_ctime as u64,
            atimensec: filestat.st_atime_nsec as u32,
            mtimensec: filestat.st_mtime_nsec as u32,
            ctimensec: filestat.st_ctime_nsec as u32,
            mode: filestat.st_mode,
            nlink: filestat.st_nlink as u32,
            uid: filestat.st_uid,
            gid: filestat.st_gid,
            rdev: filestat.st_rdev as u32,
            blksize: filestat.st_blksize as u32,
            padding: 0,
        };

        let out_arg = fuse_attr_out {
            attr_valid: 0,
            attr_valid_nsec: 0,
            dummy: 0,
            attr: attr,
        };

        Ok(request.send_arg(out_arg))
    }

    pub fn do_forget(&mut self, request: &Request) -> result::Result<u32, ExecuteError> {
        self.ino_map.remove(request.in_header.nodeid);

        Ok(0)
    }

    pub fn do_lookup(&mut self, request: &Request) -> result::Result<u32, ExecuteError> {
        let guest_mem = request.memory;
        let mut buf = vec![0u8; request.in_arg_len as usize];

        guest_mem.read_slice_at_addr(&mut buf, request.in_arg_addr)?;

        let name = CStr::from_bytes_with_nul(&buf)?;

        let ino = request.in_header.nodeid;

        let ino_fd222 = self.ino_map.get(ino)?;
        let new_fd222 = ino_fd222.lookup(name)?;

        let cached_ino = self.ino_map.identify(new_fd222);
        let used_fd = self.ino_map.get(cached_ino)?;

        let filestat = used_fd.metadata()?;

        let attr = fuse_attr {
            ino: cached_ino,
            size: filestat.st_size as u64,
            blocks: filestat.st_size as u64,
            atime: filestat.st_atime as u64,
            mtime: filestat.st_mtime as u64,
            ctime: filestat.st_ctime as u64,
            atimensec: filestat.st_atime_nsec as u32,
            mtimensec: filestat.st_mtime_nsec as u32,
            ctimensec: filestat.st_ctime_nsec as u32,
            mode: filestat.st_mode,
            nlink: filestat.st_nlink as u32,
            uid: filestat.st_uid,
            gid: filestat.st_gid,
            rdev: filestat.st_rdev as u32,
            blksize: filestat.st_blksize as u32,
            padding: 0,
        };

        let out_arg = fuse_entry_out {
            nodeid: attr.ino,
            generation: 0,
            entry_valid: 0,
            attr_valid: 0,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: attr,
        };

        Ok(request.send_arg(out_arg))
    }

    pub fn do_readdir(&mut self, request: &Request) -> result::Result<u32, ExecuteError> {
        let guest_mem = request.memory;
        let in_arg: fuse_read_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let ddddd = self.dir_map.get_mut(in_arg.fh)?;
        let mut out_arg = Vec::new();
        for (i, entry) in ddddd.iter().enumerate().skip(in_arg.offset as usize) {
            let entry = entry?;
            out_arg.push(FuseDirent {
                offset: i as u64 + 1,
                entry: entry,
            });
        }

        Ok(request.send_dirent_vec(out_arg))
    }

    pub fn do_opendir(&mut self, request: &Request) -> result::Result<u32, ExecuteError> {
        let ino = request.in_header.nodeid;
        let ino_fd = self.ino_map.get(ino)?;

        let dddd = ino_fd.opendir()?;

        let fh = self.dir_map.insert(dddd);

        let out_arg = fuse_open_out {
            fh: fh,
            open_flags: 0,
            padding: 0,
        };
        Ok(request.send_arg(out_arg))
    }

    pub fn do_releasedir(&mut self, request: &Request) -> result::Result<u32, ExecuteError> {
        let guest_mem = request.memory;
        let in_arg: fuse_release_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let fh = in_arg.fh;
        self.dir_map.remove(fh);

        Ok(request.send_err(0))
    }

    pub fn do_statfs(&mut self, request: &Request) -> result::Result<u32, ExecuteError> {
        let ino = request.in_header.nodeid;
        let ino_fd = self.ino_map.get(ino)?;

        let stat = ino_fd.fstatvfs()?;

        let out_arg = fuse_statfs_out {
            st: fuse_kstatfs {
                blocks: stat.f_blocks as u64,
                bfree: stat.f_bfree as u64,
                bavail: stat.f_bavail as u64,
                files: stat.f_files as u64,
                ffree: stat.f_ffree as u64,
                bsize: stat.f_bsize as u32,
                namelen: stat.f_namemax as u32,
                frsize: stat.f_frsize as u32,
                ..fuse_kstatfs::default()
            },
        };

        Ok(request.send_arg(out_arg))
    }

    pub fn do_access(&mut self, request: &Request) -> result::Result<u32, ExecuteError> {
        Ok(request.send_err(libc::ENOSYS))
    }

    pub fn do_mknod(&mut self, request: &Request) -> result::Result<u32, ExecuteError> {
        let guest_mem = request.memory;
        let in_arg: fuse_mknod_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let pos = request.in_arg_addr.unchecked_add(mem::size_of_val(&in_arg));
        let name_len = request.in_arg_len as usize - mem::size_of_val(&in_arg);

        let mut buf = vec![0u8; name_len];

        guest_mem.read_slice_at_addr(&mut buf, pos)?;
        buf[name_len - 1] = 0u8;
        let name = CStr::from_bytes_with_nul(&buf)?;

        let ino = request.in_header.nodeid;
        let ino_fd = self.ino_map.get(ino)?;

        match in_arg.mode & libc::S_IFMT {
            libc::S_IFDIR => {
                // TODO:
                mkdirat(ino_fd.as_raw_fd(), name, in_arg.mode)?;
            }
            libc::S_IFLNK => {
                // TODO:
            }
            _ => {
                ino_fd.mknod(name, in_arg.mode, in_arg.rdev as dev_t)?;
            }
        }

        let new_fd = ino_fd.lookup(name)?;
        let filestat = new_fd.metadata()?;
        let cached_ino = self.ino_map.identify(new_fd);

        let attr = fuse_attr {
            ino: cached_ino,
            size: filestat.st_size as u64,
            blocks: filestat.st_size as u64,
            atime: filestat.st_atime as u64,
            mtime: filestat.st_mtime as u64,
            ctime: filestat.st_ctime as u64,
            atimensec: filestat.st_atime_nsec as u32,
            mtimensec: filestat.st_mtime_nsec as u32,
            ctimensec: filestat.st_ctime_nsec as u32,
            mode: filestat.st_mode,
            nlink: filestat.st_nlink as u32,
            uid: filestat.st_uid,
            gid: filestat.st_gid,
            rdev: filestat.st_rdev as u32,
            blksize: filestat.st_blksize as u32,
            padding: 0,
        };

        let out_arg = fuse_entry_out {
            nodeid: attr.ino,
            generation: 0,
            entry_valid: 0,
            attr_valid: 0,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: attr,
        };

        Ok(request.send_arg(out_arg))
    }

    pub fn do_mkdir(&mut self, request: &Request) -> result::Result<u32, ExecuteError> {
        let guest_mem = request.memory;
        let in_arg: fuse_mkdir_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let name_len = request.in_arg_len as usize - mem::size_of_val(&in_arg);

        let mut buf = vec![0u8; name_len];

        let pos = request.in_arg_addr.unchecked_add(mem::size_of_val(&in_arg));
        guest_mem.read_slice_at_addr(&mut buf, pos)?;
        let name = CStr::from_bytes_with_nul(&buf)?;

        let mode = in_arg.mode | libc::S_IFDIR;

        let ino = request.in_header.nodeid;
        let ino_fd = self.ino_map.get(ino)?;

        with_cred(request.in_header.uid, request.in_header.gid, || {
            mkdirat(ino_fd.as_raw_fd(), name, mode)
        })?;

        let new_fd = ino_fd.lookup(name)?;
        let filestat = new_fd.metadata()?;
        let cached_ino = self.ino_map.identify(new_fd);

        let attr = fuse_attr {
            ino: cached_ino,
            size: filestat.st_size as u64,
            blocks: filestat.st_size as u64,
            atime: filestat.st_atime as u64,
            mtime: filestat.st_mtime as u64,
            ctime: filestat.st_ctime as u64,
            atimensec: filestat.st_atime_nsec as u32,
            mtimensec: filestat.st_mtime_nsec as u32,
            ctimensec: filestat.st_ctime_nsec as u32,
            mode: filestat.st_mode,
            nlink: filestat.st_nlink as u32,
            uid: filestat.st_uid,
            gid: filestat.st_gid,
            rdev: filestat.st_rdev as u32,
            blksize: filestat.st_blksize as u32,
            padding: 0,
        };

        let out_arg = fuse_entry_out {
            nodeid: attr.ino,
            generation: 0,
            entry_valid: 0,
            attr_valid: 0,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: attr,
        };

        Ok(request.send_arg(out_arg))
    }

    pub fn do_rmdir(&mut self, request: &Request) -> result::Result<u32, ExecuteError> {
        let guest_mem = request.memory;
        let mut buf = vec![0u8; request.in_arg_len as usize];

        guest_mem.read_slice_at_addr(&mut buf, request.in_arg_addr)?;

        let name = CStr::from_bytes_with_nul(&buf)?;

        let ino = request.in_header.nodeid;
        let ino_fd = self.ino_map.get(ino)?;

        unlinkat(ino_fd.as_raw_fd(), name, libc::AT_REMOVEDIR)?;

        // self.ino_map.remove(ino);
        Ok(request.send_err(0))
    }

    pub fn do_setattr(&mut self, request: &Request) -> result::Result<u32, ExecuteError> {
        let guest_mem = request.memory;
        let in_arg: fuse_setattr_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        // TODO: FATTR_FH
        // in_arg.valid | FATTR_FH

        let ino = request.in_header.nodeid;
        let ino_fd = self.ino_map.get(ino)?;

        let valid = in_arg.valid;

        if bit_intersect(valid, FATTR_MODE) {
            fchmod(ino_fd.as_raw_fd(), in_arg.mode)?;
        }

        if bit_intersect(valid, FATTR_UID | FATTR_GID) {
            let uid: uid_t = if bit_intersect(valid, FATTR_UID) {
                in_arg.uid
            } else {
                std::u32::MAX
            };

            let gid: gid_t = if bit_intersect(valid, FATTR_GID) {
                in_arg.gid
            } else {
                std::u32::MAX
            };

            fchown(ino_fd.as_raw_fd(), uid, gid)?;
        }

        let filestat = ino_fd.metadata()?;

        let attr = fuse_attr {
            ino: ino,
            size: filestat.st_size as u64,
            blocks: filestat.st_size as u64,
            atime: filestat.st_atime as u64,
            mtime: filestat.st_mtime as u64,
            ctime: filestat.st_ctime as u64,
            atimensec: filestat.st_atime_nsec as u32,
            mtimensec: filestat.st_mtime_nsec as u32,
            ctimensec: filestat.st_ctime_nsec as u32,
            mode: filestat.st_mode,
            nlink: filestat.st_nlink as u32,
            uid: filestat.st_uid,
            gid: filestat.st_gid,
            rdev: filestat.st_rdev as u32,
            blksize: filestat.st_blksize as u32,
            padding: 0,
        };

        let out_arg = fuse_attr_out {
            attr_valid: 0,
            attr_valid_nsec: 0,
            dummy: 0,
            attr: attr,
        };

        Ok(request.send_arg(out_arg))
    }

    pub fn do_unlink(&mut self, request: &Request) -> result::Result<u32, ExecuteError> {
        let guest_mem = request.memory;
        let mut buf = vec![0u8; request.in_arg_len as usize];

        guest_mem.read_slice_at_addr(&mut buf, request.in_arg_addr)?;

        let name = CStr::from_bytes_with_nul(&buf)?;

        let ino = request.in_header.nodeid;
        let ino_fd = self.ino_map.get(ino)?;

        unlinkat(ino_fd.as_raw_fd(), name, 0)?;

        Ok(request.send_err(0))
    }

    pub fn do_symlink(&mut self, request: &Request) -> result::Result<u32, ExecuteError> {
        let guest_mem = request.memory;
        let mut buf = vec![0u8; request.in_arg_len as usize];
        guest_mem.read_slice_at_addr(&mut buf, request.in_arg_addr)?;

        let (name_c, link_c) = get_c_string_slice(&buf);
        let name = CStr::from_bytes_with_nul(&name_c)?;
        let link = CStr::from_bytes_with_nul(&link_c)?;

        let ino = request.in_header.nodeid;
        let ino_fd = self.ino_map.get(ino)?;

        with_cred(request.in_header.uid, request.in_header.gid, || {
            symlinkat(ino_fd.as_raw_fd(), name, link)
        })?;

        let new_fd = ino_fd.lookup(name)?;
        let filestat = new_fd.metadata()?;
        let cached_ino = self.ino_map.identify(new_fd);

        let attr = fuse_attr {
            ino: cached_ino,
            size: filestat.st_size as u64,
            blocks: filestat.st_size as u64,
            atime: filestat.st_atime as u64,
            mtime: filestat.st_mtime as u64,
            ctime: filestat.st_ctime as u64,
            atimensec: filestat.st_atime_nsec as u32,
            mtimensec: filestat.st_mtime_nsec as u32,
            ctimensec: filestat.st_ctime_nsec as u32,
            mode: filestat.st_mode,
            nlink: filestat.st_nlink as u32,
            uid: filestat.st_uid,
            gid: filestat.st_gid,
            rdev: filestat.st_rdev as u32,
            blksize: filestat.st_blksize as u32,
            padding: 0,
        };

        let out_arg = fuse_entry_out {
            nodeid: attr.ino,
            generation: 0,
            entry_valid: 0,
            attr_valid: 0,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: attr,
        };

        Ok(request.send_arg(out_arg))
    }

    pub fn do_readlink(&mut self, request: &Request) -> result::Result<u32, ExecuteError> {
        let ino = request.in_header.nodeid;
        let ino_fd = self.ino_map.get(ino)?;

        let link = readlinkat(ino_fd.as_raw_fd(), None)?;
        Ok(request.send_slice(link.as_bytes_with_nul()))
    }
}

// fn bit_contains(token: u32, other: u32) -> bool {
//     (token & other) == other
// }

fn bit_intersect(token: u32, other: u32) -> bool {
    (token & other) != 0
}

fn get_c_string_slice(buf: &[u8]) -> (&[u8], &[u8]) {
    let pos = buf.iter().position(|&x| x == 0).unwrap();
    buf.split_at(pos + 1)
}
