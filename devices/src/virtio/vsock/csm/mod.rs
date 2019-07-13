// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

mod txbuf;

mod defs {
    /// Vsock connection TX buffer capacity.
    pub const CONN_TX_BUF_SIZE: usize = 64 * 1024;
}

#[derive(Debug)]
pub enum Error {
    TxBufFull,
    TxBufFlush(std::io::Error),
}

type Result<T> = std::result::Result<T, Error>;
