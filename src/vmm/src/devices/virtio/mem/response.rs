// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vm_memory::{Address, ByteValued, Bytes, GuestAddress};

use crate::devices::virtio::mem::VirtioMemError;
use crate::utils::usize_to_u64;
use crate::vstate::memory::GuestMemoryMmap;

// Virtio-mem response types
const VIRTIO_MEM_RESP_ACK: u16 = 0;
const VIRTIO_MEM_RESP_NACK: u16 = 1;
const VIRTIO_MEM_RESP_BUSY: u16 = 2;
const VIRTIO_MEM_RESP_ERROR: u16 = 3;

// Virtio-mem state types
const VIRTIO_MEM_STATE_PLUGGED: u16 = 0;
const VIRTIO_MEM_STATE_UNPLUGGED: u16 = 1;
const VIRTIO_MEM_STATE_MIXED: u16 = 2;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ResponseHeader {
    pub resp_type: u16,
    _padding: [u16; 3],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct StateResponse {
    pub state_type: u16,
}

// SAFETY: Plain data structures
unsafe impl ByteValued for ResponseHeader {}
unsafe impl ByteValued for StateResponse {}

#[derive(Debug, Clone, Copy)]
pub enum ResponseCode {
    Ack,
    Nack,
    Busy,
    Error,
}

impl From<ResponseCode> for u16 {
    fn from(code: ResponseCode) -> Self {
        match code {
            ResponseCode::Ack => VIRTIO_MEM_RESP_ACK,
            ResponseCode::Nack => VIRTIO_MEM_RESP_NACK,
            ResponseCode::Busy => VIRTIO_MEM_RESP_BUSY,
            ResponseCode::Error => VIRTIO_MEM_RESP_ERROR,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ResponseStateCode {
    Plugged,
    Unplugged,
    Mixed,
}

impl From<ResponseStateCode> for u16 {
    fn from(code: ResponseStateCode) -> Self {
        match code {
            ResponseStateCode::Plugged => VIRTIO_MEM_STATE_PLUGGED,
            ResponseStateCode::Unplugged => VIRTIO_MEM_STATE_UNPLUGGED,
            ResponseStateCode::Mixed => VIRTIO_MEM_STATE_MIXED,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ResponseType {
    Plug,
    Unplug,
    UnplugAll,
    State(ResponseStateCode),
    Error,
}

#[derive(Debug, Clone, Copy)]
pub struct Response {
    pub resp_code: ResponseCode,
    pub resp_type: ResponseType,
}

impl Response {
    pub fn write(
        &self,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
    ) -> Result<usize, VirtioMemError> {
        let mut num_bytes: usize = 0;
        let header = ResponseHeader {
            resp_type: self.resp_code.into(),
            _padding: [0; 3],
        };

        mem.write_obj(header, addr)
            .map_err(|_| VirtioMemError::DescriptorWriteFailed)?;
        num_bytes += std::mem::size_of::<ResponseHeader>();

        match self.resp_type {
            ResponseType::State(state) => {
                let resp = StateResponse {
                    state_type: state.into(),
                };
                mem.write_obj(
                    resp,
                    addr.checked_add(usize_to_u64(num_bytes))
                        .ok_or(VirtioMemError::DescriptorWriteFailed)?,
                )
                .map_err(|_| VirtioMemError::DescriptorWriteFailed)?;
                num_bytes += std::mem::size_of::<StateResponse>();
            }
            _ => (),
        };
        Ok(num_bytes)
    }
}
