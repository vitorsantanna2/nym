// due to code generated by JsonSchema
#![allow(clippy::field_reassign_with_default)]

use crate::{Addr, IdentityKey};
use cosmwasm_std::{Coin, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct RawDelegationData {
    pub amount: Uint128,
    pub block_height: u64,
}

impl RawDelegationData {
    pub fn new(amount: Uint128, block_height: u64) -> Self {
        RawDelegationData {
            amount,
            block_height,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, JsonSchema)]
pub struct Delegation {
    owner: Addr,
    amount: Coin,
    block_height: u64,
}

impl Delegation {
    pub fn new(owner: Addr, amount: Coin, block_height: u64) -> Self {
        Delegation {
            owner,
            amount,
            block_height,
        }
    }

    pub fn amount(&self) -> &Coin {
        &self.amount
    }

    pub fn owner(&self) -> Addr {
        self.owner.clone()
    }
}

impl Display for Delegation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} {} delegated by {} at block {}",
            self.amount.amount, self.amount.denom, self.owner, self.block_height
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, JsonSchema)]
pub struct PagedMixDelegationsResponse {
    pub node_identity: IdentityKey,
    pub delegations: Vec<Delegation>,
    pub start_next_after: Option<Addr>,
}

impl PagedMixDelegationsResponse {
    pub fn new(
        node_identity: IdentityKey,
        delegations: Vec<Delegation>,
        start_next_after: Option<Addr>,
    ) -> Self {
        PagedMixDelegationsResponse {
            node_identity,
            delegations,
            start_next_after,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, JsonSchema)]
pub struct PagedReverseMixDelegationsResponse {
    pub delegation_owner: Addr,
    pub delegated_nodes: Vec<IdentityKey>,
    pub start_next_after: Option<IdentityKey>,
}

impl PagedReverseMixDelegationsResponse {
    pub fn new(
        delegation_owner: Addr,
        delegated_nodes: Vec<IdentityKey>,
        start_next_after: Option<IdentityKey>,
    ) -> Self {
        PagedReverseMixDelegationsResponse {
            delegation_owner,
            delegated_nodes,
            start_next_after,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, JsonSchema)]
pub struct PagedGatewayDelegationsResponse {
    pub node_identity: IdentityKey,
    pub delegations: Vec<Delegation>,
    pub start_next_after: Option<Addr>,
}

impl PagedGatewayDelegationsResponse {
    pub fn new(
        node_identity: IdentityKey,
        delegations: Vec<Delegation>,
        start_next_after: Option<Addr>,
    ) -> Self {
        PagedGatewayDelegationsResponse {
            node_identity,
            delegations,
            start_next_after,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, JsonSchema)]
pub struct PagedReverseGatewayDelegationsResponse {
    pub delegation_owner: Addr,
    pub delegated_nodes: Vec<IdentityKey>,
    pub start_next_after: Option<IdentityKey>,
}

impl PagedReverseGatewayDelegationsResponse {
    pub fn new(
        delegation_owner: Addr,
        delegated_nodes: Vec<IdentityKey>,
        start_next_after: Option<IdentityKey>,
    ) -> Self {
        PagedReverseGatewayDelegationsResponse {
            delegation_owner,
            delegated_nodes,
            start_next_after,
        }
    }
}
