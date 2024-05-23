// Copyright 2022-2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;

use crate::node::client_handling::websocket::connection_handler::authenticated::RequestHandlingError;
use crate::node::storage::Storage;

use futures::channel::mpsc::UnboundedReceiver;
use futures::StreamExt;
use nym_api_requests::coconut::models::VerifyEcashCredentialResponse;
use nym_api_requests::coconut::VerifyEcashCredentialBody;

use nym_gateway_requests::models::CredentialSpendingRequest;
use nym_validator_client::nyxd::contract_traits::{EcashSigningClient, MultisigQueryClient};
use nym_validator_client::nyxd::cosmwasm_client::logs::{find_attribute, BANDWIDTH_PROPOSAL_ID};
use nym_validator_client::NymApiClient;
use nym_validator_client::{nyxd::AccountId, DirectSigningHttpRpcNyxdClient};
use tokio::{
    sync::RwLock,
    time::{interval, Duration},
};

const CRED_SENDING_INTERVAL: u64 = 300;

#[derive(Clone)]
pub struct PendingCredential {
    pub credential: CredentialSpendingRequest,
    pub address: AccountId,
    pub api_clients: Vec<NymApiClient>,
    pub proposal_id: Option<u64>,
}

impl PendingCredential {
    pub fn new(
        credential: CredentialSpendingRequest,
        address: AccountId,
        api_clients: Vec<NymApiClient>,
    ) -> Self {
        PendingCredential {
            credential,
            address,
            api_clients,
            proposal_id: None,
        }
    }
}

pub(crate) struct CredentialSender<St: Storage> {
    cred_receiver: UnboundedReceiver<PendingCredential>,
    storage: St,
    nyxd_client: Arc<RwLock<DirectSigningHttpRpcNyxdClient>>,
}

impl<St> CredentialSender<St>
where
    St: Storage + 'static,
{
    pub(crate) fn new(
        cred_receiver: UnboundedReceiver<PendingCredential>,
        storage: St,
        nyxd_client: Arc<RwLock<DirectSigningHttpRpcNyxdClient>>,
    ) -> Self {
        CredentialSender {
            cred_receiver,
            storage,
            nyxd_client,
        }
    }

    async fn create_proposal(
        &self,
        pending: &mut PendingCredential,
    ) -> Result<(), RequestHandlingError> {
        if pending.proposal_id.is_some() {
            log::trace!("Proposal already created");
            return Ok(());
        }
        if pending.credential.data.typ.is_free_pass() {
            //no proposal for freepasses
            return Ok(());
        }
        let res = self
            .nyxd_client
            .write()
            .await
            .prepare_credential(
                pending.credential.data.serial_number_b58(),
                pending.address.to_string(),
                None,
            )
            .await?;
        let proposal_id = find_attribute(&res.logs, "wasm", BANDWIDTH_PROPOSAL_ID)
            .ok_or(RequestHandlingError::ProposalIdError {
                reason: String::from("proposal id not found"),
            })?
            .value
            .parse::<u64>()
            .map_err(|_| RequestHandlingError::ProposalIdError {
                reason: String::from("proposal id could not be parsed to u64"),
            })?;

        let proposal = self
            .nyxd_client
            .read()
            .await
            .query_proposal(proposal_id)
            .await?;
        if !pending
            .credential
            .matches_serial_number(&proposal.description)?
        {
            return Err(RequestHandlingError::ProposalIdError {
                reason: String::from("proposal has different serial number"),
            });
        }
        pending.proposal_id = Some(proposal_id);
        Ok(())
    }

    async fn send_credential(pending: &mut PendingCredential) -> Result<(), RequestHandlingError> {
        if pending.credential.data.typ.is_ticketbook() && pending.proposal_id.is_none() {
            return Err(RequestHandlingError::ProposalIdError {
                reason: "proposal id is absent".to_string(),
            });
        }
        let request = VerifyEcashCredentialBody::new(
            pending.credential.data.clone(),
            pending.address.clone(),
            pending.proposal_id,
        );
        let mut failed_api = Vec::new();
        for client in &pending.api_clients {
            match client.verify_offline_credential(&request).await {
                Ok(response) => {
                    //Even if credential isn't accepted, we did contact the validator and resubmitting the same credential won't change anything. We can consider the sending as done
                    if response != VerifyEcashCredentialResponse::Accepted {
                        log::debug!(
                            "Validator {} didn't accept the credential - Reason : {}",
                            client.nym_api.current_url(),
                            response
                        );
                    }
                }
                Err(e) => {
                    log::warn!("Validator {} could not be reached. There might be a problem with the coconut endpoint - {:?}", client.nym_api.current_url(), e);
                    failed_api.push(client.clone());
                }
            }
        }
        pending.api_clients = failed_api;
        if pending.api_clients.is_empty() {
            Ok(())
        } else {
            Err(RequestHandlingError::InternalError)
        }
    }

    async fn handle_credential(&mut self, mut pending: PendingCredential) {
        if self.create_proposal(&mut pending).await.is_err()
            || Self::send_credential(&mut pending).await.is_err()
        {
            //failed to send, store credential
            if let Err(err) = self.storage.insert_pending_credential(pending).await {
                log::error!("Failed to store pending credential - {:?}", err);
            };
        }
    }

    async fn try_empty_pending(&mut self) {
        log::debug!("Trying to send unsent payments");
        let pending = match self.storage.get_all_pending_credential().await {
            Err(err) => {
                log::error!("Failed to retrieve pending credential - {:?}", err);
                return;
            }
            Ok(res) => res,
        };

        for (id, mut pending) in pending {
            if self.create_proposal(&mut pending).await.is_ok() {
                //send successful, remove credential from storage
                if let Err(err) = self.storage.remove_pending_credential(id).await {
                    log::error!("Failed to remove pending credential - {:?}", err);
                }
                if Self::send_credential(&mut pending).await.is_err() {
                    //we didn't send to everyone one
                    if let Err(err) = self.storage.insert_pending_credential(pending).await {
                        log::error!("Failed to store pending credential - {:?}", err);
                    };
                }
            }
        }
    }

    async fn run(mut self, mut shutdown: nym_task::TaskClient) {
        log::info!("Starting Ecash CredentialSender");
        let mut interval = interval(Duration::from_secs(CRED_SENDING_INTERVAL));

        while !shutdown.is_shutdown() {
            tokio::select! {
                biased;
                _ = shutdown.recv() => {
                    log::trace!("client_handling::credentialSender : received shutdown");
                },
                Some(credential) = self.cred_receiver.next() => self.handle_credential(credential).await,
                _ = interval.tick() => self.try_empty_pending().await,

            }
        }
    }

    pub(crate) fn start(self, shutdown: nym_task::TaskClient) {
        tokio::spawn(async move { self.run(shutdown).await });
    }
}
