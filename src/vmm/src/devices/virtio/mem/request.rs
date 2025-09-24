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

#[derive(Debug, Clone, Copy)]
pub enum ResponseType {
    Ack,
    Nack,
    Busy,
    Error,
}

impl From<ResponseType> for u16 {
    fn from(code: ResponseType) -> Self {
        match code {
            ResponseType::Ack => virtio_mem::VIRTIO_MEM_RESP_ACK,
            ResponseType::Nack => virtio_mem::VIRTIO_MEM_RESP_NACK,
            ResponseType::Busy => virtio_mem::VIRTIO_MEM_RESP_BUSY,
            ResponseType::Error => virtio_mem::VIRTIO_MEM_RESP_ERROR,
        }
        .try_into()
        .unwrap()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BlockRangeState {
    Plugged,
    Unplugged,
    Mixed,
}

impl From<BlockRangeState> for virtio_mem::virtio_mem_resp_state {
    fn from(code: BlockRangeState) -> Self {
        virtio_mem::virtio_mem_resp_state {
            state: match code {
                BlockRangeState::Plugged => virtio_mem::VIRTIO_MEM_STATE_PLUGGED,
                BlockRangeState::Unplugged => virtio_mem::VIRTIO_MEM_STATE_UNPLUGGED,
                BlockRangeState::Mixed => virtio_mem::VIRTIO_MEM_STATE_MIXED,
            }
            .try_into()
            .unwrap(),
        }
    }
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
            type_: resp.resp_type.into(),
            ..Default::default()
        };
        if let Some(state) = resp.state {
            out.u.state = state.into();
        }
        out
    }
}
