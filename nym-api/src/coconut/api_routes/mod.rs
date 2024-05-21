// Copyright 2023-2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use crate::coconut::api_routes::helpers::build_credentials_response;
use crate::coconut::error::{CoconutError, Result};
use crate::coconut::helpers::{accepted_vote_err, blind_sign};
use crate::coconut::state::State;
use crate::coconut::storage::CoconutStorageExt;
use k256::ecdsa::signature::Verifier;
use nym_api_requests::coconut::models::{
    CredentialsRequestBody, EpochCredentialsResponse, FreePassNonceResponse, FreePassRequest,
    IssuedCredentialResponse, IssuedCredentialsResponse,
};
use nym_api_requests::coconut::{
    BlindSignRequestBody, BlindedSignatureResponse, PartialCoinIndicesSignatureResponse,
    PartialExpirationDateSignatureResponse, VerifyEcashCredentialBody,
};
use nym_coconut_dkg_common::types::EpochId;
use nym_compact_ecash::error::CompactEcashError;
use nym_credentials::coconut::utils::{
    cred_exp_date_timestamp, freepass_exp_date_timestamp, today_timestamp,
};
use nym_validator_client::nyxd::Coin;
use rand::rngs::OsRng;
use rand::RngCore;
use rocket::serde::json::Json;
use rocket::State as RocketState;
use std::ops::Deref;
use time::OffsetDateTime;

mod helpers;

#[get("/free-pass-nonce")]
pub async fn get_current_free_pass_nonce(
    state: &RocketState<State>,
) -> Result<Json<FreePassNonceResponse>> {
    debug!("Received free pass nonce request");

    let current_nonce = state.freepass_nonce.read().await;
    debug!("the current expected nonce is {current_nonce:?}");

    Ok(Json(FreePassNonceResponse {
        current_nonce: *current_nonce,
    }))
}

#[post("/free-pass", data = "<freepass_request_body>")]
pub async fn post_free_pass(
    freepass_request_body: Json<FreePassRequest>,
    state: &RocketState<State>,
) -> Result<Json<BlindedSignatureResponse>> {
    debug!("Received free pass sign request");
    trace!("body: {:?}", freepass_request_body);

    //check expiration date validity
    if freepass_request_body.expiration_date > freepass_exp_date_timestamp() {
        return Err(CoconutError::TooLongFreePass {
            expiry_date: OffsetDateTime::from_unix_timestamp(
                freepass_request_body
                    .expiration_date
                    .try_into()
                    .map_err(|_| CoconutError::InvalidQueryArguments)?,
            )
            .unwrap(),
        });
    }

    // grab the admin of the bandwidth contract
    let Some(authorised_admin) = state.get_bandwidth_contract_admin().await? else {
        error!("our bandwidth contract does not have an admin set! We won't be able to migrate the contract! We should redeploy it ASAP");
        return Err(CoconutError::MissingBandwidthContractAdmin);
    };

    // derive the address out of the provided pubkey
    let requester = match freepass_request_body
        .cosmos_pubkey
        .account_id(authorised_admin.prefix())
    {
        Ok(address) => address,
        Err(err) => {
            return Err(CoconutError::AdminAccountDerivationFailure {
                formatted_source: err.to_string(),
            })
        }
    };
    debug!("derived the following address out of the provided public key: {requester}. Going to check it against the authorised admin ({authorised_admin})");

    if &requester != authorised_admin {
        return Err(CoconutError::UnauthorisedFreePassAccount {
            requester,
            authorised_admin: authorised_admin.clone(),
        });
    }

    // get the write lock on the nonce to block other requests (since we don't need concurrency and nym is the only one getting them)
    let mut current_nonce = state.freepass_nonce.write().await;
    debug!("the current expected nonce is {current_nonce:?}");

    if *current_nonce != freepass_request_body.used_nonce {
        return Err(CoconutError::InvalidNonce {
            current: *current_nonce,
            received: freepass_request_body.used_nonce,
        });
    }

    // check if we have the signing key available
    debug!("checking if we actually have coconut keys derived...");
    let maybe_keypair_guard = state.coconut_keypair.get().await;
    let Some(keypair_guard) = maybe_keypair_guard.as_ref() else {
        return Err(CoconutError::KeyPairNotDerivedYet);
    };
    let Some(signing_key) = keypair_guard.as_ref() else {
        return Err(CoconutError::KeyPairNotDerivedYet);
    };

    let tm_pubkey = freepass_request_body.tendermint_pubkey();

    // currently accounts (excluding validators) don't use ed25519 and are secp256k1-based
    let Some(secp256k1_pubkey) = tm_pubkey.secp256k1() else {
        return Err(CoconutError::UnsupportedNonSecp256k1Key);
    };

    // make sure the signature actually verifies
    secp256k1_pubkey
        .verify(
            &freepass_request_body.used_nonce,
            &freepass_request_body.nonce_signature,
        )
        .map_err(|_| CoconutError::FreePassSignatureVerificationFailure)?;

    // produce the partial signature
    debug!("producing the partial credential");
    let blinded_signature = blind_sign(
        freepass_request_body.deref(),
        &signing_key.keys.secret_key(),
    )?;

    // update the number of issued free passes
    state.storage.increment_issued_freepasses().await?;

    // update the nonce
    OsRng.fill_bytes(current_nonce.as_mut_slice());

    // finally return the credential to the client
    Ok(Json(BlindedSignatureResponse { blinded_signature }))
}

#[post("/blind-sign", data = "<blind_sign_request_body>")]
//  Until we have serialization and deserialization traits we'll be using a crutch
pub async fn post_blind_sign(
    blind_sign_request_body: Json<BlindSignRequestBody>,
    state: &RocketState<State>,
) -> Result<Json<BlindedSignatureResponse>> {
    debug!("Received blind sign request");
    trace!("body: {:?}", blind_sign_request_body);

    // check if we already issued a credential for this tx hash
    debug!(
        "checking if we have already issued credential for this tx_hash (hash: {})",
        blind_sign_request_body.tx_hash
    );
    if let Some(blinded_signature) = state
        .already_issued(blind_sign_request_body.tx_hash)
        .await?
    {
        return Ok(Json(BlindedSignatureResponse { blinded_signature }));
    }

    // check if we have the signing key available
    debug!("checking if we actually have coconut keys derived...");
    let maybe_keypair_guard = state.coconut_keypair.get().await;
    let Some(keypair_guard) = maybe_keypair_guard.as_ref() else {
        return Err(CoconutError::KeyPairNotDerivedYet);
    };
    let Some(signing_key) = keypair_guard.as_ref() else {
        return Err(CoconutError::KeyPairNotDerivedYet);
    };

    //check if account was blacklisted
    let pub_key_bs58 = blind_sign_request_body.ecash_pubkey.to_base58_string();
    let blacklist_response = state
        .client
        .get_blacklisted_account(pub_key_bs58.clone())
        .await?;
    if let Some(account) = blacklist_response.account {
        if account.public_key() == pub_key_bs58 {
            //Theoretically useless check
            return Err(CoconutError::BlacklistedAccount);
        }
    }

    // get the transaction details of the claimed deposit
    debug!("getting transaction details from the chain");
    let tx = state
        .get_transaction(blind_sign_request_body.tx_hash)
        .await?;

    //check expiration date validity
    if blind_sign_request_body.expiration_date > cred_exp_date_timestamp() {
        return Err(
            CompactEcashError::ExpirationDate("Invalid expiration date".to_string()).into(),
        );
    }

    // check validity of the request
    debug!("fully validating received request");
    state.validate_request(&blind_sign_request_body, tx).await?;

    // produce the partial signature
    debug!("producing the partial credential");
    let blinded_signature = blind_sign(
        blind_sign_request_body.deref(),
        &signing_key.keys.secret_key(),
    )?;

    // store the information locally
    debug!("storing the issued credential in the database");
    state
        .store_issued_credential(blind_sign_request_body.into_inner(), &blinded_signature)
        .await?;

    // finally return the credential to the client
    Ok(Json(BlindedSignatureResponse { blinded_signature }))
}

#[post("/verify-bandwidth-credential", data = "<verify_credential_body>")]
pub async fn verify_bandwidth_credential(
    verify_credential_body: Json<VerifyCredentialBody>,
    state: &RocketState<State>,
) -> Result<Json<VerifyCredentialResponse>> {
    let proposal_id = verify_credential_body.proposal_id;
    let credential_data = &verify_credential_body.credential_data;
    let epoch_id = credential_data.epoch_id;
    let theta = &credential_data.verify_credential_request;

    let voucher_value: u64 = if credential_data.typ.is_voucher() {
        credential_data
            .get_bandwidth_attribute()
            .ok_or(CoconutError::MissingBandwidthValue)?
            .parse()
            .map_err(|source| CoconutError::VoucherValueParsingFailure { source })?
    } else {
        return Err(CoconutError::NotABandwidthVoucher {
            typ: credential_data.typ,
        });
    };

    // TODO: introduce a check to make sure we haven't already voted for this proposal to prevent DDOS

    let proposal = state.client.get_proposal(proposal_id).await?;

    // Proposal description is the blinded serial number
    if !theta.has_blinded_serial_number(&proposal.description)? {
        return Err(CoconutError::IncorrectProposal {
            reason: String::from("incorrect blinded serial number in description"),
        });
    }
    let proposed_release_funds =
        funds_from_cosmos_msgs(proposal.msgs).ok_or(CoconutError::IncorrectProposal {
            reason: String::from("action is not to release funds"),
        })?;
    // Credential has not been spent before, and is on its way of being spent
    let credential_status = state
        .client
        .get_spent_credential(theta.blinded_serial_number_bs58())
        .await?
        .spend_credential
        .ok_or(CoconutError::InvalidCredentialStatus {
            status: String::from("Inexistent"),
        })?
        .status();
    if credential_status != SpendCredentialStatus::InProgress {
        return Err(CoconutError::InvalidCredentialStatus {
            status: format!("{:?}", credential_status),
        });
    }
    let verification_key = state.verification_key(epoch_id).await?;
    let params = bandwidth_credential_params();
    let mut vote_yes = credential_data.verify(params, &verification_key);

    vote_yes &= Coin::from(proposed_release_funds)
        == Coin::new(voucher_value as u128, state.mix_denom.clone());

    // Vote yes or no on the proposal based on the verification result
    let ret = state
        .client
        .vote_proposal(proposal_id, vote_yes, None)
        .await;
    accepted_vote_err(ret)?;

    Ok(Json(VerifyCredentialResponse::new(vote_yes)))
}

#[get("/epoch-credentials/<epoch>")]
pub async fn epoch_credentials(
    epoch: EpochId,
    state: &RocketState<State>,
) -> Result<Json<EpochCredentialsResponse>> {
    let issued = state.storage.get_epoch_credentials(epoch).await?;

    let response = if let Some(issued) = issued {
        issued.into()
    } else {
        EpochCredentialsResponse {
            epoch_id: epoch,
            first_epoch_credential_id: None,
            total_issued: 0,
        }
    };

    Ok(Json(response))
}

#[get("/issued-credential/<id>")]
pub async fn issued_credential(
    id: i64,
    state: &RocketState<State>,
) -> Result<Json<IssuedCredentialResponse>> {
    let issued = state.storage.get_issued_credential(id).await?;

    let credential = if let Some(issued) = issued {
        Some(issued.try_into()?)
    } else {
        None
    };

    Ok(Json(IssuedCredentialResponse { credential }))
}

#[post("/issued-credentials", data = "<params>")]
pub async fn issued_credentials(
    params: Json<CredentialsRequestBody>,
    state: &RocketState<State>,
) -> Result<Json<IssuedCredentialsResponse>> {
    let params = params.into_inner();

    if params.pagination.is_some() && !params.credential_ids.is_empty() {
        return Err(CoconutError::InvalidQueryArguments);
    }

    let credentials = if let Some(pagination) = params.pagination {
        state
            .storage
            .get_issued_credentials_paged(pagination)
            .await?
    } else {
        state
            .storage
            .get_issued_credentials(params.credential_ids)
            .await?
    };

    build_credentials_response(credentials).map(Json)
}

#[get("/expiration-date-signatures")]
pub async fn expiration_date_signatures(
    state: &RocketState<State>,
) -> Result<Json<PartialExpirationDateSignatureResponse>> {
    let expiration_date_signatures = state.get_exp_date_signatures().await?;

    Ok(Json(PartialExpirationDateSignatureResponse::new(
        &expiration_date_signatures,
    )))
}

#[get("/expiration-date-signatures/<timestamp>")]
pub async fn expiration_date_signatures_timestamp(
    timestamp: u64,
    state: &RocketState<State>,
) -> Result<Json<PartialExpirationDateSignatureResponse>> {
    let expiration_date_signatures = state.get_exp_date_signatures_timestamp(timestamp).await?;
    Ok(Json(PartialExpirationDateSignatureResponse::new(
        &expiration_date_signatures,
    )))
}

#[get("/coin-indices-signatures")]
pub async fn coin_indices_signatures(
    state: &RocketState<State>,
) -> Result<Json<PartialCoinIndicesSignatureResponse>> {
    let coin_indices_signatures = state.get_coin_indices_signatures().await?;
    Ok(Json(PartialCoinIndicesSignatureResponse::new(
        &coin_indices_signatures,
    )))
}
