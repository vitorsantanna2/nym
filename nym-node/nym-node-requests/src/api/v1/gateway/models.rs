// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0


use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Gateway {
    pub client_interfaces: ClientInterfaces,
}

#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Wireguard {
    #[cfg_attr(feature = "openapi", schema(example = 51820, default = 51820))]
    pub port: u16,

    pub public_key: String,
}

#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ClientInterfaces {
    pub wireguard: Option<Wireguard>,

    pub mixnet_websockets: Option<WebSockets>,
    // pub mixnet_tcp:
}

#[derive(Serialize, Debug, Clone, Copy)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WebSockets {
    #[cfg_attr(feature = "openapi", schema(example = 9000, default = 9000))]
    pub ws_port: u16,

    pub wss_port: Option<u16>,
}