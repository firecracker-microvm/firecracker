// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vm_memory::{Address, ByteValued, GuestAddress};

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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

#[derive(Debug, Clone, Eq, PartialEq)]
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

    pub(crate) fn is_ack(&self) -> bool {
        self.resp_type == ResponseType::Ack
    }

    pub(crate) fn is_error(&self) -> bool {
        self.resp_type == ResponseType::Error
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

#[cfg(test)]
mod test_util {
    use super::*;

    // Implement the reverse conversions to use in test code.

    impl From<Request> for virtio_mem::virtio_mem_req {
        fn from(req: Request) -> virtio_mem::virtio_mem_req {
            match req {
                Request::Plug(r) => virtio_mem::virtio_mem_req {
                    type_: virtio_mem::VIRTIO_MEM_REQ_PLUG.try_into().unwrap(),
                    u: virtio_mem::virtio_mem_req__bindgen_ty_1 {
                        plug: virtio_mem::virtio_mem_req_plug {
                            addr: r.addr.raw_value(),
                            nb_blocks: r.nb_blocks.try_into().unwrap(),
                            ..Default::default()
                        },
                    },
                    ..Default::default()
                },
                Request::Unplug(r) => virtio_mem::virtio_mem_req {
                    type_: virtio_mem::VIRTIO_MEM_REQ_UNPLUG.try_into().unwrap(),
                    u: virtio_mem::virtio_mem_req__bindgen_ty_1 {
                        unplug: virtio_mem::virtio_mem_req_unplug {
                            addr: r.addr.raw_value(),
                            nb_blocks: r.nb_blocks.try_into().unwrap(),
                            ..Default::default()
                        },
                    },
                    ..Default::default()
                },
                Request::UnplugAll => virtio_mem::virtio_mem_req {
                    type_: virtio_mem::VIRTIO_MEM_REQ_UNPLUG_ALL.try_into().unwrap(),
                    ..Default::default()
                },
                Request::State(r) => virtio_mem::virtio_mem_req {
                    type_: virtio_mem::VIRTIO_MEM_REQ_STATE.try_into().unwrap(),
                    u: virtio_mem::virtio_mem_req__bindgen_ty_1 {
                        state: virtio_mem::virtio_mem_req_state {
                            addr: r.addr.raw_value(),
                            nb_blocks: r.nb_blocks.try_into().unwrap(),
                            ..Default::default()
                        },
                    },
                    ..Default::default()
                },
                Request::Unsupported(t) => virtio_mem::virtio_mem_req {
                    type_: t.try_into().unwrap(),
                    ..Default::default()
                },
            }
        }
    }

    impl From<virtio_mem::virtio_mem_resp> for Response {
        fn from(resp: virtio_mem::virtio_mem_resp) -> Self {
            Response {
                resp_type: match resp.type_.into() {
                    virtio_mem::VIRTIO_MEM_RESP_ACK => ResponseType::Ack,
                    virtio_mem::VIRTIO_MEM_RESP_NACK => ResponseType::Nack,
                    virtio_mem::VIRTIO_MEM_RESP_BUSY => ResponseType::Busy,
                    virtio_mem::VIRTIO_MEM_RESP_ERROR => ResponseType::Error,
                    t => panic!("Invalid response type: {:?}", t),
                },
                // There is no way to know whether this is present or not as it depends on the
                // request types. Callers should ignore this value if the request wasn't STATE
                /// SAFETY: test code only. Uninitialized values are 0 and recognized as PLUGGED.
                state: Some(unsafe {
                    match resp.u.state.state.into() {
                        virtio_mem::VIRTIO_MEM_STATE_PLUGGED => BlockRangeState::Plugged,
                        virtio_mem::VIRTIO_MEM_STATE_UNPLUGGED => BlockRangeState::Unplugged,
                        virtio_mem::VIRTIO_MEM_STATE_MIXED => BlockRangeState::Mixed,
                        t => panic!("Invalid state: {:?}", t),
                    }
                }),
            }
        }
    }
}
