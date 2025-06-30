// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem;

use vm_memory::{Address, ByteValued, Bytes, GuestAddress};

use crate::devices::virtio::mem::VirtioMemError;
use crate::devices::virtio::queue::DescriptorChain;
use crate::utils::usize_to_u64;
use crate::vstate::memory::GuestMemoryMmap;

// Virtio-mem request types
const VIRTIO_MEM_REQ_PLUG: u16 = 0;
const VIRTIO_MEM_REQ_UNPLUG: u16 = 1;
const VIRTIO_MEM_REQ_UNPLUG_ALL: u16 = 2;
const VIRTIO_MEM_REQ_STATE: u16 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestType {
    Plug,
    Unplug,
    UnplugAll,
    State,
    Unsupported(u16),
}

impl From<u16> for RequestType {
    fn from(value: u16) -> Self {
        match value {
            VIRTIO_MEM_REQ_PLUG => RequestType::Plug,
            VIRTIO_MEM_REQ_UNPLUG => RequestType::Unplug,
            VIRTIO_MEM_REQ_UNPLUG_ALL => RequestType::UnplugAll,
            VIRTIO_MEM_REQ_STATE => RequestType::State,
            t => RequestType::Unsupported(t),
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct VirtioMemRequestHeader {
    req_type: u16,
    _padding: [u16; 3],
}

unsafe impl ByteValued for VirtioMemRequestHeader {}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
// The same struct is used for PLUG, UNPLUG, and STATE
pub struct VirtioMemRequest {
    pub addr: u64,
    pub nb_blocks: u16,
    _padding: [u16; 3],
}

unsafe impl ByteValued for VirtioMemRequest {}

#[derive(Debug, Clone, Copy)]
pub struct Request {
    pub req_type: RequestType,
    // not present in UNPLUG_ALL
    pub request: Option<VirtioMemRequest>,
    pub resp_addr: GuestAddress,
    pub resp_len: u32,
    pub index: u16,
}

impl Request {
    pub fn parse(
        avail_desc: &DescriptorChain,
        guest_mem: &GuestMemoryMmap,
    ) -> Result<Request, VirtioMemError> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(VirtioMemError::UnexpectedWriteOnlyDescriptor);
        }

        if avail_desc.len < mem::size_of::<VirtioMemRequestHeader>() as u32 {
            return Err(VirtioMemError::DescriptorLengthTooSmall);
        }

        let request_header: VirtioMemRequestHeader = guest_mem
            .read_obj(avail_desc.addr)
            .map_err(|_| VirtioMemError::DescriptorReadFailed)?;

        let req_type: RequestType = request_header.req_type.into();

        let request = match req_type {
            RequestType::Plug | RequestType::Unplug | RequestType::State => {
                if avail_desc.len
                    < (mem::size_of::<VirtioMemRequestHeader>()
                        + mem::size_of::<VirtioMemRequest>()) as u32
                {
                    return Err(VirtioMemError::DescriptorLengthTooSmall);
                }
                let request: VirtioMemRequest = guest_mem
                    .read_obj(
                        avail_desc
                            .addr
                            .checked_add(usize_to_u64(mem::size_of::<VirtioMemRequestHeader>()))
                            .ok_or(VirtioMemError::DescriptorReadFailed)?,
                    )
                    .map_err(|_| VirtioMemError::DescriptorReadFailed)?;
                Some(request)
            }
            RequestType::UnplugAll => None,
            _ => return Err(VirtioMemError::UnknownRequestType(req_type)),
        };

        let resp_desc = avail_desc
            .next_descriptor()
            .ok_or(VirtioMemError::DescriptorChainTooShort)?;

        // The response MUST always be writable.
        if !resp_desc.is_write_only() {
            return Err(VirtioMemError::UnexpectedReadOnlyDescriptor);
        }

        if resp_desc.len < 1 {
            // TODO fix check
            return Err(VirtioMemError::DescriptorLengthTooSmall);
        }

        Ok(Request {
            req_type,
            request,
            resp_addr: resp_desc.addr,
            resp_len: resp_desc.len,
            index: avail_desc.index,
        })
    }
}
