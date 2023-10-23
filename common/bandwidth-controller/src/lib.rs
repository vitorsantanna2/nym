// Copyright 2021-2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use crate::error::BandwidthControllerError;
use nym_compact_ecash::scheme::{Payment, Wallet};
use nym_compact_ecash::setup::{setup, GroupParameters};
use nym_compact_ecash::{generate_keypair_user, Base58, PayInfo};
use nym_credential_storage::error::StorageError;
use nym_credential_storage::storage::Storage;
use nym_credentials::obtain_aggregate_verification_key;
use nym_validator_client::coconut::all_coconut_api_clients;
use nym_validator_client::nyxd::contract_traits::DkgQueryClient;
use std::str::FromStr;

pub mod acquire;
pub mod error;

pub struct BandwidthController<C, St> {
    storage: St,
    client: C,
}

impl<C, St: Storage> BandwidthController<C, St> {
    pub fn new(storage: St, client: C) -> Self {
        BandwidthController { storage, client }
    }

    pub fn storage(&self) -> &St {
        &self.storage
    }

    pub async fn prepare_ecash_credential(
        &self,
    ) -> Result<(Payment, String, i64), BandwidthControllerError>
    where
        C: DkgQueryClient + Sync + Send,
        <St as Storage>::StorageError: Send + Sync + 'static,
    {
        let ecash_credential = self
            .storage
            .get_next_ecash_credential()
            .await
            .map_err(|err| BandwidthControllerError::CredentialStorageError(Box::new(err)))?;
        let voucher_value = u64::from_str(&ecash_credential.voucher_value)
            .map_err(|_| StorageError::InconsistentData)?;
        let voucher_info = ecash_credential.voucher_info.clone();
        let wallet = Wallet::try_from_bs58(ecash_credential.wallet)?;
        let epoch_id = u64::from_str(&ecash_credential.epoch_id)
            .map_err(|_| StorageError::InconsistentData)?;

        let coconut_api_clients = all_coconut_api_clients(&self.client, epoch_id).await?;

        let verification_key = obtain_aggregate_verification_key(&coconut_api_clients).await?;

        let some_L_I_guess = 100; //SW: TEMPORARY VALUE
        let params = setup(some_L_I_guess);
        let sk_user = generate_keypair_user(&GroupParameters::new()?).secret_key(); //SW : TODO Retreive key fro mcredential storage
        let pay_info = PayInfo { info: [0u8; 32] }; //SW: TEMPORARY VALUE. Waiting for actual computation
        let nb_tickets = 1u64; //SW: TEMPORARY VALUE, what should we put there?

        // the below would only be executed once we know where we want to spend it (i.e. which gateway and stuff)

        let (payment, _) = wallet.spend(
            &params,
            &verification_key,
            &sk_user,
            &pay_info,
            false,
            nb_tickets,
        )?;

        //SW : TODO Store new wallet

        Ok((payment, wallet.to_bs58(), ecash_credential.id))
    }

    pub async fn update_ecash_credential(
        &self,
        wallet: String,
        id: i64,
    ) -> Result<(), BandwidthControllerError>
    where
        <St as Storage>::StorageError: Send + Sync + 'static,
    {
        // JS: shouldn't we send some contract/validator/gateway message here to actually, you know,
        // consume it?
        self.storage
            .update_ecash_credential(wallet, id)
            .await
            .map_err(|err| BandwidthControllerError::CredentialStorageError(Box::new(err)))
    }
}

impl<C, St> Clone for BandwidthController<C, St>
where
    C: Clone,
    St: Storage + Clone,
{
    fn clone(&self) -> Self {
        BandwidthController {
            storage: self.storage.clone(),
            client: self.client.clone(),
        }
    }
}
