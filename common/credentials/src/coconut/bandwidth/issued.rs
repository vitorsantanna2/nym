// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use crate::coconut::bandwidth::bandwidth_credential_params;
use crate::coconut::bandwidth::freepass::FreePassIssuedData;
use crate::coconut::bandwidth::issuance::{
    BandwidthCredentialIssuanceDataVariant, IssuanceBandwidthCredential,
};
use crate::coconut::bandwidth::voucher::BandwidthVoucherIssuedData;
use crate::coconut::bandwidth::{CredentialSpendingData, CredentialType};
use crate::coconut::utils::scalar_serde_helper;
use crate::error::Error;
use nym_credentials_interface::prove_bandwidth_credential;
use nym_credentials_interface::{
    Parameters, PrivateAttribute, PublicAttribute, Signature, VerificationKey,
};
use nym_validator_client::nym_api::EpochId;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const CURRENT_SERIALIZATION_REVISION: u8 = 1;

#[derive(Zeroize, Serialize, Deserialize)]
pub enum BandwidthCredentialIssuedDataVariant {
    Voucher(BandwidthVoucherIssuedData),
    FreePass(FreePassIssuedData),
}

impl<'a> From<&'a BandwidthCredentialIssuanceDataVariant> for BandwidthCredentialIssuedDataVariant {
    fn from(value: &'a BandwidthCredentialIssuanceDataVariant) -> Self {
        match value {
            BandwidthCredentialIssuanceDataVariant::Voucher(voucher) => {
                BandwidthCredentialIssuedDataVariant::Voucher(voucher.into())
            }
            BandwidthCredentialIssuanceDataVariant::FreePass(freepass) => {
                BandwidthCredentialIssuedDataVariant::FreePass(freepass.into())
            }
        }
    }
}

impl From<FreePassIssuedData> for BandwidthCredentialIssuedDataVariant {
    fn from(value: FreePassIssuedData) -> Self {
        BandwidthCredentialIssuedDataVariant::FreePass(value)
    }
}

impl From<BandwidthVoucherIssuedData> for BandwidthCredentialIssuedDataVariant {
    fn from(value: BandwidthVoucherIssuedData) -> Self {
        BandwidthCredentialIssuedDataVariant::Voucher(value)
    }
}

impl BandwidthCredentialIssuedDataVariant {
    pub fn info(&self) -> CredentialType {
        match self {
            BandwidthCredentialIssuedDataVariant::Voucher(..) => CredentialType::Voucher,
            BandwidthCredentialIssuedDataVariant::FreePass(..) => CredentialType::FreePass,
        }
    }

    // currently this works under the assumption of there being a single unique public attribute for given variant
    pub fn public_value_plain(&self) -> String {
        match self {
            BandwidthCredentialIssuedDataVariant::Voucher(voucher) => voucher.value_plain(),
            BandwidthCredentialIssuedDataVariant::FreePass(freepass) => {
                freepass.expiry_date_plain()
            }
        }
    }
}

// the only important thing to zeroize here are the private attributes, the rest can be made fully public for what we're concerned
#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct IssuedBandwidthCredential {
    // private attributes
    /// a random secret value generated by the client used for double-spending detection
    #[serde(with = "scalar_serde_helper")]
    serial_number: PrivateAttribute,

    /// a random secret value generated by the client used to bind multiple credentials together
    #[serde(with = "scalar_serde_helper")]
    binding_number: PrivateAttribute,

    /// the underlying aggregated signature on the attributes
    #[zeroize(skip)]
    signature: Signature,

    /// data specific to given bandwidth credential, for example a value for bandwidth voucher and expiry date for the free pass
    variant_data: BandwidthCredentialIssuedDataVariant,

    /// type of the bandwdith credential hashed onto a scalar
    #[serde(with = "scalar_serde_helper")]
    type_prehashed: PublicAttribute,

    /// Specifies the (DKG) epoch id when this credential has been issued
    epoch_id: EpochId,
}

impl IssuedBandwidthCredential {
    pub fn new(
        serial_number: PrivateAttribute,
        binding_number: PrivateAttribute,
        signature: Signature,
        variant_data: BandwidthCredentialIssuedDataVariant,
        type_prehashed: PublicAttribute,
        epoch_id: EpochId,
    ) -> Self {
        IssuedBandwidthCredential {
            serial_number,
            binding_number,
            signature,
            variant_data,
            type_prehashed,
            epoch_id,
        }
    }

    pub fn current_serialization_revision(&self) -> u8 {
        CURRENT_SERIALIZATION_REVISION
    }

    /// Pack (serialize) this credential data into a stream of bytes using v1 serializer.
    pub fn pack_v1(&self) -> Vec<u8> {
        use bincode::Options;
        // safety: our data format is stable and thus the serialization should not fail
        make_storable_bincode_serializer().serialize(self).unwrap()
    }

    /// Unpack (deserialize) the credential data from the given bytes using v1 serializer.
    pub fn unpack_v1(bytes: &[u8]) -> Result<Self, Error> {
        use bincode::Options;
        Ok(make_storable_bincode_serializer().deserialize(bytes)?)
    }

    pub fn randomise_signature(&mut self) {
        let signature_prime = self.signature.randomise(bandwidth_credential_params());
        self.signature = signature_prime.0
    }

    pub fn default_parameters() -> Parameters {
        IssuanceBandwidthCredential::default_parameters()
    }

    pub fn typ(&self) -> CredentialType {
        self.variant_data.info()
    }

    pub fn get_plain_public_attributes(&self) -> Vec<String> {
        vec![
            self.variant_data.public_value_plain(),
            self.typ().to_string(),
        ]
    }

    pub fn prepare_for_spending(
        &self,
        verification_key: &VerificationKey,
    ) -> Result<CredentialSpendingData, Error> {
        let params = bandwidth_credential_params();

        let verify_credential_request = prove_bandwidth_credential(
            params,
            verification_key,
            &self.signature,
            &self.serial_number,
            &self.binding_number,
        )?;

        Ok(CredentialSpendingData {
            embedded_private_attributes: IssuanceBandwidthCredential::PRIVATE_ATTRIBUTES as usize,
            verify_credential_request,
            public_attributes_plain: self.get_plain_public_attributes(),
            typ: self.typ(),
            epoch_id: self.epoch_id,
        })
    }
}

fn make_storable_bincode_serializer() -> impl bincode::Options {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_big_endian()
        .with_varint_encoding()
}
