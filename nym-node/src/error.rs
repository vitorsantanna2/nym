// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NymNodeError {
    #[error("failed to bind the HTTP API to {bind_address}: {source}")]
    HttpBindFailure {
        bind_address: SocketAddr,
        source: hyper::Error,
    },

    #[error("failed to use nym-node requests: {source}")]
    RequestError {
        #[from]
        source: nym_node_requests::error::Error,
    },

    #[error("unimplemented")]
    Unimplemented,
}
