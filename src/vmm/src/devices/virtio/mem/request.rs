// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vm_memory::{ByteValued, GuestAddress};

use crate::devices::virtio::generated::virtio_mem;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestedRange {
    pub(crate) addr: GuestAddress,
    pub(crate) nb_blocks: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Request {
    Plug(RequestedRange),
    Unplug(RequestedRange),
    UnplugAll,
    State(RequestedRange),
    Unsupported(u32),
}

// SAFETY: this is safe, trust me bro
unsafe impl ByteValued for virtio_mem::virtio_mem_req {}

impl From<virtio_mem::virtio_mem_req> for Request {
    fn from(req: virtio_mem::virtio_mem_req) -> Self {
        match req.type_.into() {
            // SAFETY: union type is checked in the match
            virtio_mem::VIRTIO_MEM_REQ_PLUG => unsafe {
                Request::Plug(RequestedRange {
                    addr: GuestAddress(req.u.plug.addr),
                    nb_blocks: req.u.plug.nb_blocks.into(),
                })
            },
            // SAFETY: union type is checked in the match
            virtio_mem::VIRTIO_MEM_REQ_UNPLUG => unsafe {
                Request::Unplug(RequestedRange {
                    addr: GuestAddress(req.u.unplug.addr),
                    nb_blocks: req.u.unplug.nb_blocks.into(),
                })
            },
            virtio_mem::VIRTIO_MEM_REQ_UNPLUG_ALL => Request::UnplugAll,
            // SAFETY: union type is checked in the match
            virtio_mem::VIRTIO_MEM_REQ_STATE => unsafe {
                Request::State(RequestedRange {
                    addr: GuestAddress(req.u.state.addr),
                    nb_blocks: req.u.state.nb_blocks.into(),
                })
            },
            t => Request::Unsupported(t),
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(clippy::cast_possible_truncation)]
pub enum ResponseType {
    Ack = virtio_mem::VIRTIO_MEM_RESP_ACK as u16,
    Nack = virtio_mem::VIRTIO_MEM_RESP_NACK as u16,
    Busy = virtio_mem::VIRTIO_MEM_RESP_BUSY as u16,
    Error = virtio_mem::VIRTIO_MEM_RESP_ERROR as u16,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(clippy::cast_possible_truncation)]
pub enum BlockRangeState {
    Plugged = virtio_mem::VIRTIO_MEM_STATE_PLUGGED as u16,
    Unplugged = virtio_mem::VIRTIO_MEM_STATE_UNPLUGGED as u16,
    Mixed = virtio_mem::VIRTIO_MEM_STATE_MIXED as u16,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub resp_type: ResponseType,
    // Only for State requests
    pub state: Option<BlockRangeState>,
}

impl Response {
    pub(crate) fn error() -> Self {
        Response {
            resp_type: ResponseType::Error,
            state: None,
        }
    }

    pub(crate) fn ack() -> Self {
        Response {
            resp_type: ResponseType::Ack,
            state: None,
        }
    }

    pub(crate) fn ack_with_state(state: BlockRangeState) -> Self {
        Response {
            resp_type: ResponseType::Ack,
            state: Some(state),
        }
    }
}

// SAFETY: Plain data structures
unsafe impl ByteValued for virtio_mem::virtio_mem_resp {}

impl From<Response> for virtio_mem::virtio_mem_resp {
    fn from(resp: Response) -> Self {
        let mut out = virtio_mem::virtio_mem_resp {
            type_: resp.resp_type as u16,
            ..Default::default()
        };
        if let Some(state) = resp.state {
            out.u.state.state = state as u16;
        }
        out
    }
}
