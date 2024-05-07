// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use crate::config::RewardingRatios;
use nym_compact_ecash::error::CompactEcashError;
use nym_validator_client::nym_api::error::NymAPIError;
use nym_validator_client::nyxd::error::NyxdError;
use nym_validator_client::nyxd::tx::ErrorReport;
use nym_validator_client::nyxd::{AccountId, Coin, Hash};
use std::io;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NymRewarderError {
    #[error("experienced internal database error: {0}")]
    InternalDatabaseError(#[from] sqlx::Error),

    #[error("failed to perform startup SQL migration: {0}")]
    StartupMigrationFailure(#[from] sqlx::migrate::MigrateError),

    #[error(
    "failed to load config file using path '{}'. detailed message: {source}", path.display()
    )]
    ConfigLoadFailure {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error(
    "failed to save config file using path '{}'. detailed message: {source}", path.display()
    )]
    ConfigSaveFailure {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to initialise paths")]
    PathInitialisationFailure {
        #[source]
        source: io::Error,
    },

    #[error("there already exists a config file at: {}. if you want to overwrite its content, use --force flag", path.display())]
    ExistingConfig { path: PathBuf },

    // TODO: I think this one should get split into more, explicit, variants
    #[error(transparent)]
    NyxdFailure(#[from] NyxdError),

    #[error("the provided rewarding ratios don't add up to 1. ratios: {ratios:?}")]
    InvalidRewardingRatios { ratios: RewardingRatios },

    #[error("chain scraping failure: {source}")]
    ScraperFailure {
        #[from]
        source: nyxd_scraper::error::ScraperError,
    },

    // this should never happen but unwrapping everywhere was more cumbersome than just propagating the error
    #[error("failed to determine epoch boundaries: {0}")]
    TimeComponentFailure(#[from] time::error::ComponentRange),

    #[error(
        "could not convert operator address: {operator_address} to a nym account address: {source}"
    )]
    MalformedBech32Address {
        operator_address: String,
        #[source]
        source: ErrorReport,
    },

    #[error(
        "could not convert validator public key: {public_key} into a consensus address: {source}"
    )]
    MalformedConsensusPublicKey {
        public_key: String,
        #[source]
        source: ErrorReport,
    },

    #[error("somehow the total voting power was negative: {val}")]
    NegativeTotalVotingPower { val: i64 },

    #[error("somehow the signed blocks was negative: {val}")]
    NegativeSignedBlocks { val: i64 },

    #[error("could not find details for validator {consensus_address}")]
    MissingValidatorDetails { consensus_address: String },

    #[error("api url ({raw}) provided by {runner_account} is invalid: {source}")]
    MalformedApiUrl {
        raw: String,
        runner_account: AccountId,
        #[source]
        source: url::ParseError,
    },

    #[error("failed to resolve nym-api query: {0}")]
    ApiQueryFailure(#[from] NymAPIError),

    #[error("operator {runner_account} didn't return all requested credentials! requested {requested} but got only {received}")]
    IncompleteRequest {
        runner_account: AccountId,
        requested: usize,
        received: usize,
    },

    #[error("the following private attribute commitment is malformed: {raw}: {source}")]
    MalformedCredentialCommitment {
        raw: String,
        #[source]
        source: CompactEcashError,
    },

    #[error("the partial verification key for runner {runner} is malformed: {source}")]
    MalformedPartialVerificationKey {
        runner: String,
        #[source]
        source: CompactEcashError,
    },

    #[error("could not verify the blinded credential")]
    BlindVerificationFailure,

    #[error("the same deposit transaction ({tx_hash}) has been used for multiple issued credentials! {first} and {other}")]
    DuplicateDepositHash {
        tx_hash: Hash,
        first: i64,
        other: i64,
    },

    #[error("could not find the deposit value in the event of transaction {tx_hash}")]
    DepositValueNotFound { tx_hash: Hash },

    #[error("could not find the deposit info in the event of transaction {tx_hash}")]
    DepositInfoNotFound { tx_hash: Hash },

    #[error("the provided deposit value of transaction {tx_hash} is inconsistent. got '{request:?}' while the value on chain is '{on_chain}'")]
    InconsistentDepositValue {
        tx_hash: Hash,
        request: Option<String>,
        on_chain: String,
    },

    #[error("the provided deposit info  of transaction {tx_hash} is inconsistent. got '{request:?}' while the value on chain is '{on_chain}'")]
    InconsistentDepositInfo {
        tx_hash: Hash,
        request: Option<String>,
        on_chain: String,
    },

    #[error("the current rewarder balance is insufficient to start the process. The epoch budget is: {} while we currently have {}. (the minimum is set to {})", .0.epoch_budget, .0.balance, .0.minimum)]
    InsufficientRewarderBalance(Box<InsufficientBalance>),

    #[error("the scraper websocket endpoint hasn't been provided")]
    UnavailableWebsocketUrl,

    #[error("block signing rewarding is enabled, but the validator whitelist is empty")]
    EmptyBlockSigningWhitelist,

    #[error("credential issuance rewarding is enabled, but the validator whitelist is empty")]
    EmptyCredentialIssuanceWhitelist,

    #[error("there were no validators to reward in this epoch")]
    NoValidatorsToReward,
}

#[derive(Debug)]
pub struct InsufficientBalance {
    pub epoch_budget: Coin,
    pub balance: Coin,
    pub minimum: Coin,
}
